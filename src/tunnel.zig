const std = @import("std");
const AES = std.crypto.core.aes.Aes128;
const GCM = std.crypto.aead.aes_gcm.Aes128Gcm;
const pbkdf2 = std.crypto.pwhash.pbkdf2;
const SealedBox = std.crypto.nacl.SealedBox;

const Self = @This();

pub const KeyPair = SealedBox.KeyPair;
pub const public_length = SealedBox.public_length;

pub const Reader = std.io.Reader(Self, anyerror, read);
pub const Writer = std.io.Writer(Self, anyerror, write);

peer: [SealedBox.public_length]u8,
secret: [GCM.key_length]u8,
stream: std.net.Stream,
keypair: SealedBox.KeyPair,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream, keypair: KeyPair) Self {
    return .{
        .peer = undefined,
        .secret = undefined,
        .stream = stream,
        .keypair = keypair,
        .allocator = allocator,
    };
}

pub fn handshake(self: *Self, peer: [SealedBox.public_length]u8) !void {
    std.crypto.random.bytes(self.secret[0..]);
    // challenge-response authentication
    var sealed: [GCM.key_length + SealedBox.seal_length]u8 = undefined;
    var response: [GCM.key_length]u8 = undefined;
    var challenge: [GCM.key_length]u8 = undefined;

    try SealedBox.seal(sealed[0..], self.secret[0..], peer);
    _ = try self.stream.write(sealed[0..]);

    _ = try self.stream.read(sealed[0..]);
    try SealedBox.open(&challenge, sealed[0..], self.keypair);

    try SealedBox.seal(sealed[0..], &challenge, peer);
    _ = try self.stream.write(sealed[0..]);

    _ = try self.stream.read(sealed[0..]);
    try SealedBox.open(&response, &sealed, self.keypair);

    if (!std.mem.eql(u8, &response, &self.secret))
        return error.ChallengeResponse;

    try pbkdf2(
        &response,
        &self.secret,
        &peer,
        10000,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );
    try pbkdf2(
        &self.secret,
        &challenge,
        &self.keypair.public_key,
        10000,
        std.crypto.auth.hmac.sha2.HmacSha256,
    );

    for (0..self.secret.len) |i| self.secret[i] ^= response[i];

    std.mem.copyForwards(u8, self.peer[0..], &peer);
}

pub fn deinit(self: *Self) void {
    self.stream.close();
    @memset(self.secret[0..], 0);
}

pub fn write(self: Self, buffer: []const u8) !usize {
    try self.writeFrame(buffer);
    return buffer.len;
}

pub fn read(self: Self, buffer: []u8) !usize {
    const data = try self.readFrame(self.allocator);
    defer self.allocator.free(data);
    const limit = if (data.len > buffer.len) buffer.len else data.len;
    std.mem.copyForwards(u8, buffer[0..], data[0..limit]);
    return data.len;
}

/// conforms to Reader interface
pub fn reader(self: Self) Reader {
    return .{ .context = self };
}

/// conforms with writer interface
pub fn writer(self: Self) Writer {
    return .{ .context = self };
}

/// Frame {
///     nonce: [GCM.nonce_length]u8,
///     bufLen: [4]u8,
///     padLen: [1]u8,
///     payload: [?]u8,
///     padding: [padLen]u8,
///     tag[GCM.tag_length]u8,
/// }
pub fn writeFrame(self: Self, data: []const u8) !void {
    const padLen = 16 - (GCM.nonce_length + 5 + data.len + GCM.tag_length) % 16;
    const bufLen = GCM.nonce_length + 5 + data.len + padLen + GCM.tag_length;
    const buffer = try self.allocator.alloc(u8, bufLen);
    defer self.allocator.free(buffer);

    std.mem.writeInt(
        u32,
        buffer[GCM.nonce_length..][0..4],
        @truncate(buffer.len - (4 + GCM.nonce_length)),
        .big,
    );

    const tag = buffer[buffer.len - GCM.tag_length ..][0..GCM.tag_length];
    const nonce = buffer[0..GCM.nonce_length];
    const plain = buffer[nonce.len + 4 .. buffer.len - tag.len];

    var prng = std.rand.DefaultPrng.init(
        @truncate(@as(u128, @bitCast(std.time.nanoTimestamp()))),
    );
    prng.random().bytes(nonce);

    buffer[4 + nonce.len] = @truncate(padLen);
    std.mem.copyForwards(u8, plain[1..], data);
    prng.random().bytes(plain[plain.len - padLen ..]);

    GCM.encrypt(
        plain,
        tag,
        plain,
        &self.peer,
        nonce.*,
        self.secret,
    );

    const aes = AES.initEnc(self.secret);
    aes.encrypt(buffer[0..16], buffer[0..16]);

    var sent: usize = 0;
    while (sent < buffer.len) {
        sent += try self.stream.write(buffer[sent..]);
    }
}

pub fn readFrame(self: Self, allocator: std.mem.Allocator) ![]u8 {
    var nonceLen: [4 + GCM.nonce_length]u8 = undefined;

    var received: usize = 0;
    while (received < nonceLen.len) {
        received += try self.stream.read(nonceLen[0..]);
        if (received == 0) return error.BrokenPipe;
    }

    // AES-ECB decrypt nonce + bufLen
    const aes = AES.initDec(self.secret);
    aes.decrypt(nonceLen[0..], &nonceLen);

    const length = std.mem.readInt(u32, nonceLen[GCM.nonce_length..][0..4], .big);
    const buffer = try self.allocator.alloc(u8, length);
    defer self.allocator.free(buffer);

    received = 0;
    while (received < buffer.len) {
        received += try self.stream.read(buffer[received..]);
    }

    const tag = buffer[buffer.len - GCM.tag_length ..][0..GCM.tag_length];
    const nonce = nonceLen[0..GCM.nonce_length];
    const plain = buffer[0 .. buffer.len - tag.len];

    try GCM.decrypt(
        plain,
        plain,
        tag.*,
        &self.keypair.public_key,
        nonce.*,
        self.secret,
    );

    return try allocator.dupe(u8, plain[1 .. plain.len - plain[0]]);
}
