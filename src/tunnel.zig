const std = @import("std");
const AES = std.crypto.core.aes.Aes256;
const GCM = std.crypto.aead.aes_gcm.Aes256Gcm;
const Kyber = std.crypto.kem.kyber_d00.Kyber768;
const X25519 = std.crypto.dh.X25519;

const Self = @This();

pub const Mode = enum(u8) {
    client,
    server,
};

pub const PublicKey = struct {
    ecc: [X25519.public_length]u8,
    kyber: Kyber.PublicKey,
    pub fn toBytes(self: PublicKey) [X25519.public_length + Kyber.PublicKey.bytes_length]u8 {
        var buf: [X25519.public_length + Kyber.PublicKey.bytes_length]u8 = undefined;
        defer @memset(&buf, 0);
        std.mem.copyForwards(u8, &buf, &self.ecc);
        std.mem.copyForwards(u8, buf[self.ecc.len..], &self.kyber.toBytes());
        return buf;
    }

    pub fn fromBytes(buf: []const u8) !PublicKey {
        return .{
            .ecc = buf[0..X25519.public_length].*,
            .kyber = try Kyber.PublicKey.fromBytes(buf[X25519.public_length..][0..Kyber.PublicKey.bytes_length]),
        };
    }
};

pub const PrivateKey = struct {
    ecc: [X25519.secret_length]u8,
    kyber: Kyber.SecretKey,

    pub fn toBytes(self: PrivateKey) [X25519.secret_length + Kyber.SecretKey.bytes_length]u8 {
        var buf: [X25519.secret_length + Kyber.SecretKey.bytes_length]u8 = undefined;
        defer @memset(&buf, 0);
        std.mem.copyForwards(u8, &buf, &self.ecc);
        std.mem.copyForwards(u8, buf[self.ecc.len..], &self.kyber.toBytes());
        return buf;
    }

    pub fn fromBytes(buf: []const u8) !PrivateKey {
        return .{
            .ecc = buf[0..X25519.secret_length].*,
            .kyber = try Kyber.SecretKey.fromBytes(buf[X25519.public_length..][0..Kyber.SecretKey.bytes_length]),
        };
    }
};

pub const KeyPair = struct {
    public: PublicKey,
    private: PrivateKey,
    pub fn generate() KeyPair {
        const ecc = X25519.KeyPair.generate();
        const kyber = Kyber.KeyPair.generate();
        return .{
            .public = .{
                .ecc = ecc.public_key,
                .kyber = kyber.public_key,
            },
            .private = .{
                .ecc = ecc.secret_key,
                .kyber = kyber.secret_key,
            },
        };
    }
};

pub const Reader = std.io.Reader(Self, anyerror, read);
pub const Writer = std.io.Writer(Self, anyerror, write);

prng: *std.Random.Xoshiro256,
secret: [GCM.key_length]u8,
stream: std.net.Stream,
keypair: KeyPair,
allocator: std.mem.Allocator,

pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream, keypair: ?KeyPair) Self {
    const prng = allocator.create(std.Random.Xoshiro256) catch unreachable;
    prng.seed(std.crypto.random.int(u64));
    return .{
        .prng = prng,
        .secret = undefined,
        .stream = stream,
        .keypair = keypair orelse KeyPair.generate(),
        .allocator = allocator,
    };
}

/// use X25519Kyber768 to perform key-exchange.
pub fn keyExchange(self: *Self, mode: Mode) !void {
    var sha3 = std.crypto.hash.sha3.Sha3_384.init(.{});
    var digest: [std.crypto.hash.sha3.Sha3_384.digest_length]u8 = undefined;

    defer @memset(&digest, 0);

    switch (mode) {
        .client => {
            const kyber_public = self.keypair.public.kyber.toBytes();
            try self.stream.writeAll(&self.keypair.public.ecc);
            try self.stream.writeAll(&kyber_public);

            var ecc_public: [X25519.public_length]u8 = undefined;
            var kyber_ciphertext: [Kyber.ciphertext_length]u8 = undefined;
            if (try self.stream.readAll(&ecc_public) != ecc_public.len) return error.BrokenPipe;
            if (try self.stream.readAll(&kyber_ciphertext) != kyber_ciphertext.len) return error.BrokenPipe;

            // TODO: optionally, verify peer's public key

            var shared_ecc = try X25519.scalarmult(self.keypair.private.ecc, ecc_public);
            var shared_kyber = try self.keypair.private.kyber.decaps(&kyber_ciphertext);
            defer {
                @memset(&shared_ecc, 0);
                @memset(&shared_kyber, 0);
            }

            sha3.update(&shared_ecc);
            sha3.update(&shared_kyber);
        },
        .server => {
            var ecc_public: [X25519.public_length]u8 = undefined;
            var kyber_public: [Kyber.PublicKey.bytes_length]u8 = undefined;
            if (try self.stream.readAll(&ecc_public) != ecc_public.len) return error.BrokenPipe;
            if (try self.stream.readAll(&kyber_public) != kyber_public.len) return error.BrokenPipe;

            // TODO: optionally, verify peer's public key

            const kyber = try Kyber.PublicKey.fromBytes(&kyber_public);
            var shared_ecc = try X25519.scalarmult(self.keypair.private.ecc, ecc_public);
            var shared_kyber = kyber.encaps(null);
            defer {
                @memset(&shared_ecc, 0);
                @memset(&shared_kyber.shared_secret, 0);
            }

            try self.stream.writeAll(&self.keypair.public.ecc);
            try self.stream.writeAll(&shared_kyber.ciphertext);

            sha3.update(&shared_ecc);
            sha3.update(&shared_kyber.shared_secret);
        },
    }

    sha3.final(&digest);

    std.mem.copyForwards(u8, self.secret[0..], digest[0..self.secret.len]);
}

pub fn deinit(self: *Self) void {
    self.stream.close();
    @memset(self.secret[0..], 0);
    self.allocator.destroy(self.prng);
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
    return limit;
}

/// conforms to Reader interface
pub fn reader(self: Self) Reader {
    return .{ .context = self };
}

/// conforms with writer interface
pub fn writer(self: Self) Writer {
    return .{ .context = self };
}

/// The frame contents looks like the following:
///
///    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |  len  |        nonce          |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |p|           payload           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |              ...              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |         ... padding           |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///   |              tag              |
///   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// Note that each tick mark represents a byte position
///
/// The payload has variable length and the padding is used to ensure the frame length is divisible by 16. The amount
/// of padding is indicated as a single byte `p`. The field `len` is the length of payload + padding + tag + 1.
///
/// The packet can also be represented in the following structure:
///
/// Frame {
///     bufLen: u32,
///     nonce: [GCM.nonce_length]u8,
///     padLen: u8,
///     payload: [bufLen]u8,
///     padding: [padLen]u8,
///     tag[GCM.tag_length]u8,
/// }
///
/// The first 16 bytes (len + nonce) are encrypted with AES256-ECB. The following N bytes are AES256-GCM encrypted
/// ( N = 1 + payload.len + padding.len ). Only the last 16 bytes (tag) are left unencrypted.
///
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

    self.prng.random().bytes(nonce);

    buffer[4 + nonce.len] = @truncate(padLen);
    std.mem.copyForwards(u8, plain[1..], data);
    self.prng.random().bytes(plain[plain.len - padLen ..]);

    GCM.encrypt(
        plain,
        tag,
        plain,
        "",
        nonce.*,
        self.secret,
    );

    const aes = AES.initEnc(self.secret);
    aes.encrypt(buffer[0..16], buffer[0..16]);

    try self.stream.writeAll(buffer[0..]);
}

/// When reading a frame, the receiver must decrypt the first 16 bytes to figure the length of data and the nonce, that
/// is then used to read and decrypt the following data.
pub fn readFrame(self: Self, allocator: std.mem.Allocator) ![]u8 {
    var nonceLen: [4 + GCM.nonce_length]u8 = undefined;

    if (try self.stream.readAll(nonceLen[0..]) != nonceLen.len) return error.BrokenPipe;

    // AES-ECB decrypt nonce + bufLen
    const aes = AES.initDec(self.secret);
    aes.decrypt(nonceLen[0..], &nonceLen);

    const length = std.mem.readInt(u32, nonceLen[GCM.nonce_length..][0..4], .big);
    const buffer = try self.allocator.alloc(u8, length);
    defer self.allocator.free(buffer);

    if (try self.stream.readAll(buffer[0..]) != buffer.len) return error.BrokenPipe;

    const tag = buffer[buffer.len - GCM.tag_length ..][0..GCM.tag_length];
    const nonce = nonceLen[0..GCM.nonce_length];
    const plain = buffer[0 .. buffer.len - tag.len];

    try GCM.decrypt(
        plain,
        plain,
        tag.*,
        "",
        nonce.*,
        self.secret,
    );

    return try allocator.dupe(u8, plain[1 .. plain.len - plain[0]]);
}
