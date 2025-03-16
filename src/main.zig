const std = @import("std");
const Tunnel = @import("tunnel.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const mode: Tunnel.Mode = if (std.process.hasEnvVarConstant("CLIENT")) .client else .server;

    const stream = if (mode == .client) try std.net.tcpConnectToAddress(std.net.Address.initIp4([4]u8{ 127, 0, 0, 1 }, 1337)) else server: {
        std.debug.print("Listenning...\n", .{});
        var server = try std.net.Address.initIp4([4]u8{ 0, 0, 0, 0 }, 1337).listen(
            .{ .reuse_address = true },
        );
        defer server.deinit();

        const client = try server.accept();
        std.debug.print("Accepted!\n", .{});
        break :server client.stream;
    };

    var tunnel = Tunnel.init(allocator, stream, null);
    defer tunnel.deinit();

    try tunnel.keyExchange(mode);
    std.debug.print("Handshake OK\n", .{});

    _ = try tunnel.writeFrame("Hello!");
    std.debug.print("Sent data\n", .{});
    const data = try tunnel.readFrame(allocator);
    defer allocator.free(data);
    std.debug.print("Received: {s}\n", .{data});
}
