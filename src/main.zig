const std = @import("std");
const Tunnel = @import("tunnel.zig");

pub fn main() !void {
    const keypair = try Tunnel.KeyPair.create(null);
    const allocator = std.heap.page_allocator;

    const stream = if (std.process.hasEnvVarConstant("CLIENT")) try std.net.tcpConnectToAddress(std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 1337)) else server: {
        std.debug.print("Listenning...\n", .{});
        var server = try std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 1337).listen(
            .{ .reuse_address = true },
        );
        defer server.deinit();

        const client = try server.accept();
        std.debug.print("Accepted!\n", .{});
        break :server client.stream;
    };

    var peer: [Tunnel.public_length]u8 = undefined;
    _ = try stream.write(&keypair.public_key);
    std.debug.print("Sent my key\n", .{});
    _ = try stream.read(peer[0..]);
    std.debug.print("Received peer's key\n", .{});

    var tunnel = Tunnel.init(allocator, stream, keypair);
    defer tunnel.deinit();

    try tunnel.handshake(peer);
    std.debug.print("Handshake OK\n", .{});

    _ = try tunnel.writeFrame("AA");
    std.debug.print("Sent data\n", .{});
    const data = try tunnel.readFrame(allocator);
    defer allocator.free(data);
    std.debug.print("Received: {s}\n", .{data});
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit(); // try commenting this out and see if zig detects the memory leak!
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}
