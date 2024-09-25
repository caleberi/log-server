const std = @import("std");
const Mutex = std.Thread.Mutex;
const Allocator = std.mem.Allocator;
const logger = std.log.scoped(.download_buffer);
const DownloadBuffer = @This();
const HashCtx = struct {
    pub fn hash(self: @This(), key: BufferId) u64 {
        _ = self;
        const k = key.get_key();
        defer key.allocator.free(k);
        return std.hash.Wyhash.hash(0, k);
    }

    pub fn eql(self: @This(), key: BufferId, other: BufferId) bool {
        _ = self;
        const k = key.get_key();
        const o = other.get_key();

        defer {
            key.allocator.free(k);
            other.allocator.free(o);
        }
        return std.mem.eql(u8, k, o);
    }
};
const HashMap = std.HashMap(BufferId, BufferedItem, HashCtx, std.hash_map.default_max_load_percentage);

pub const CallbackHandler = *const fn (*DownloadBuffer, *BufferId, *BufferedItem) anyerror!void;
pub const WatchHandler = fn (self: *DownloadBuffer, callback: CallbackHandler) anyerror!void;

///  Buffered item is a stored by a download structure
/// to hold data in memory for a specified time before writing to
/// disk depending on the time set of the item.
pub const BufferedItem = struct {
    // append offset to commit on disk
    offset: i64,
    /// byte data to be buffered down
    data: []u8,
    // destination file to commit to
    dest: []const u8,
};

pub const BufferId = struct {
    // download handle
    handle: i64,
    // unique timestamp for a possible buffer creation
    timestamp: i64,
    written: bool,
    allocator: Allocator,

    fn get_key(self: @This()) []const u8 {
        return std.fmt.allocPrint(self.allocator, "buffer_{d}_{d}", .{ self.handle, self.timestamp }) catch @panic("could not allocate memory");
    }
};

/// For tracking our download item
items: HashMap,

/// for synchronizing download
mutex: Mutex = Mutex{},

allocator: Allocator,

/// time before the next cleanup activity
cleanup_interval: u64 = 3 * std.time.s_per_min,

enable_watcher: bool = false,

pub fn hash_key(allocator: Allocator, handle: i64, timestamp: i64) []const u8 {
    return try std.fmt.allocPrint(allocator, "buffer_{d}_{d}", .{ handle, timestamp });
}

fn newBufferId(allocator: Allocator) BufferId {
    return BufferId{
        .handle = std.time.milliTimestamp() + std.time.ms_per_s * 60,
        .timestamp = std.time.milliTimestamp(),
        .written = false,
        .allocator = allocator,
    };
}

pub fn init(allocator: Allocator, cleanup_interval: u64, enable_watcher: bool) DownloadBuffer {
    return .{
        .allocator = allocator,
        .items = HashMap.init(allocator),
        .cleanup_interval = cleanup_interval * std.time.s_per_min,
        .enable_watcher = enable_watcher,
    };
}

pub fn deinit(self: *DownloadBuffer) void {
    self.mutex.lock();
    defer self.mutex.unlock();

    var item_iterator = self.items.iterator();
    defer self.items.deinit();

    while (item_iterator.next()) |entry| {
        // clean the data in the entry
        self.allocator.free(entry.value_ptr.data);
        self.allocator.free(entry.value_ptr.dest);

        if (self.items.remove(entry.key_ptr.*)) {
            entry.key_ptr.* = undefined;
            entry.value_ptr.* = undefined;
        }
    }
}

pub fn set(self: *DownloadBuffer, data: []u8, dest: []const u8, offset: i64) !void {
    self.mutex.lock();
    defer self.mutex.unlock();

    const bufferId: BufferId = newBufferId(self.allocator);
    const item = BufferedItem{
        .offset = offset,
        .data = try self.allocator.dupe(u8, data),
        .dest = try self.allocator.dupe(u8, dest),
    };

    try self.items.put(bufferId, item);
}

pub fn watch(self: *DownloadBuffer, callback: CallbackHandler) !void {
    while (self.enable_watcher) {
        std.time.sleep(self.cleanup_interval * std.time.ns_per_s);
        var mp_iterator = self.items.iterator();
        while (mp_iterator.next()) |entry| {
            self.mutex.lock();
            defer self.mutex.unlock();
            try callback(self, entry.key_ptr, entry.value_ptr);
        }
    }
}

fn handler(self: *DownloadBuffer, key: *BufferId, item: *BufferedItem) !void {
    try std.fs.cwd().writeFile(.{
        .sub_path = item.dest,
        .data = item.data,
    });

    self.allocator.free(item.data);
    self.allocator.free(item.dest);

    if (self.items.remove(key.*)) {
        var e: *BufferedItem = @constCast(item);
        e.data = undefined;
        e.dest = undefined;
    }
}

test "create a download buffer" {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .verbose_log = true }){};
    std.debug.assert(gpa.detectLeaks() == false);
    const allocator = gpa.allocator();

    var download_buffer = DownloadBuffer.init(allocator, 30, false);
    defer download_buffer.deinit();

    // Generate a single buffer Id for insertion
    var data = [_]u8{ 65, 66, 67 };
    try download_buffer.set(data[0..], "test.log", 0);

    var download_buffer_watcher = try std.Thread.spawn(.{}, watch, .{ &download_buffer, handler });
    defer download_buffer_watcher.join();
}
