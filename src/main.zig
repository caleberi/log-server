const std = @import("std");
const Allocator = std.mem.Allocator;
const express = @import("./lib/server.zig");
const Downloader = @import("./lib/download_buffer.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    std.debug.assert(gpa.detectLeaks() == false);
    const allocator = gpa.allocator();

    const ip_addr = "127.0.0.1";
    const port = 5469;
    const thread_count = 0;

    var router = try express.Router.init(allocator, ip_addr, port, .debug, std.io.getStdOut(), thread_count);
    defer router.deinit();

    var download_buffer = Downloader.init(allocator, 5, true);
    defer download_buffer.deinit();

    const wt = try std.Thread.spawn(.{}, Downloader.watch, .{ &download_buffer, callback });
    defer wt.join();

    try router.addDependency("download_buffer", &download_buffer);

    try router.get("/health-check", handle_checks);
    try router.post("/save-logs", handle_logs);

    try router.listen();
}

fn handle_logs(allocator: Allocator, ctx: express.RContext) anyerror!void {
    const logInfoDef = struct {
        data: []const u8,
        dest: []const u8,
    };

    const log_data = try std.json.parseFromSlice(logInfoDef, allocator, ctx.request.body, .{
        .ignore_unknown_fields = true,
        .duplicate_field_behavior = .use_last,
    });
    defer log_data.deinit();

    var download_buffer: *Downloader = @alignCast(@ptrCast(ctx.deps.get("download_buffer")));
    const data = @constCast(log_data.value.data);
    const dest = log_data.value.dest;
    try download_buffer.set(data, dest, 0);
    try ctx.response.setBody("log recieved");
}

fn handle_checks(allocator: Allocator, ctx: express.RContext) anyerror!void {
    _ = allocator;
    try ctx.response.setBody("log recieved");
}

fn callback(self: *Downloader, key: *Downloader.BufferId, item: *Downloader.BufferedItem) !void {
    const cwd = std.fs.cwd();
    var exist = true;
    std.fs.cwd().access(item.dest, .{}) catch {
        exist = false;
    };

    if (!exist) {
        const file = try cwd.createFile(item.dest, .{ .truncate = false });
        defer file.close();
    }

    var file: std.fs.File = try cwd.openFile(item.dest, .{ .mode = .read_write });
    defer file.close();

    const stat = try file.stat();
    try file.seekTo(stat.size);
    _ = try file.write(item.data);

    self.allocator.free(item.data);
    self.allocator.free(item.dest);

    if (self.items.remove(key.*)) {
        item.data = undefined;
        item.dest = undefined;
    }
}
