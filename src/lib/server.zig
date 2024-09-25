const std = @import("std");
const http = @import("std").http;
const mem = @import("std").mem;
const downloader = @import("./download_buffer.zig");

const Request = http.Server.Request;
const Response = http.Server.Response;
const Allocator = mem.Allocator;

const Thread = std.Thread;
const SpawnConfig = std.Thread.SpawnConfig;
const WaitGroup = std.Thread.WaitGroup;
const spawn = Thread.spawn;
const LogLevel = std.log.Level;

const defaultNumberOfThread = 2;
const RouteList = std.StringHashMap(Route);
const DependencyList = std.StringHashMap(*anyopaque);

pub const RContext = struct {
    request: *HttpRequest,
    response: *HttpResponse,
    deps: *DependencyList,
};

pub const HandlerFn = *const fn (allocator: Allocator, context: RContext) anyerror!void;

const HashCtx = struct {
    pub fn hash(self: @This(), key: []const u8) u64 {
        _ = self;
        return std.hash.Wyhash.hash(0, key);
    }

    pub fn eql(self: @This(), key: []const u8, other: []const u8) bool {
        _ = self;
        return std.mem.eql(u8, key, other);
    }
};

pub const HashMap = std.HashMap([]const u8, []const u8, HashCtx, std.hash_map.default_max_load_percentage);

fn hash_key(allocator: Allocator, method: http.Method, path: []const u8) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{any}-{s}", .{ method, path });
}

const Route = struct {
    path: []const u8,
    method: http.Method,
    handlerFn: HandlerFn,

    pub fn init(path: []const u8, method: http.Method, callback: HandlerFn) Route {
        return .{ .handlerFn = callback, .method = method, .path = path };
    }

    pub fn deinit(self: *Route) void {
        self.* = undefined;
    }

    pub fn get_key(self: *Route, allocator: Allocator) ![]const u8 {
        return try hash_key(allocator, self.method, self.path);
    }
};

pub const HttpRequest = struct {
    params: HashMap,
    headers: *Request.Head,
    request: *Request,
    raw_headers: HashMap,
    uri: std.Uri,
    allocator: Allocator,
    queries: HashMap,
    body: []u8 = undefined,

    fn init(allocator: Allocator, uri: std.Uri, route_path: []const u8, request: *Request) !HttpRequest {
        var http_request = HttpRequest{
            .allocator = allocator,
            .request = request,
            .headers = &request.head,
            .uri = uri,
            .raw_headers = HashMap.init(allocator),
            .queries = HashMap.init(allocator),
            .params = HashMap.init(allocator),
        };

        var header_itr = request.iterateHeaders();
        while (header_itr.next()) |hd| {
            try http_request.raw_headers.put(
                try allocator.dupe(u8, hd.name),
                try allocator.dupe(u8, hd.value),
            );
        }

        try http_request.parseRouteParams(request.head.target, route_path);
        try http_request.parseQueries(request.head.target);
        var body_reader = try request.reader();

        var content_list = std.ArrayList(u8).init(allocator);
        try body_reader.readAllArrayList(&content_list, @as(usize, http_request.headers.content_length.?));
        http_request.body = try content_list.toOwnedSlice();

        return http_request;
    }

    fn parseRouteParams(self: *HttpRequest, uri_path: []const u8, route_path: []const u8) !void {
        var path_fragments = std.mem.tokenize(u8, uri_path, "/");
        var route_path_itr = std.mem.tokenize(u8, route_path, "/");

        while (route_path_itr.next()) |route_segment| {
            const uri_segment = path_fragments.next() orelse break;

            if (std.mem.startsWith(u8, route_segment, ":")) {
                const param_name = route_segment[1..];
                try self.params.put(try self.allocator.dupe(u8, param_name), try self.allocator.dupe(u8, uri_segment));
            } else if (!std.mem.eql(u8, route_segment, uri_segment)) {
                return error.RouteDoesNotMatch;
            }
        }

        if (path_fragments.next() != null) {
            return error.RouteDoesNotMatch;
        }
    }

    fn parseQueries(self: *HttpRequest, path: []const u8) !void {
        var path_fragments = std.mem.split(u8, path, "?");
        _ = path_fragments.first(); // ignore the first part - path section
        const query_fragment = path_fragments.next() orelse return;
        var token_itr = std.mem.tokenize(u8, query_fragment, "&");
        while (token_itr.next()) |q| {
            var q_itr = std.mem.split(u8, q, "=");
            const key = q_itr.first();
            const value = q_itr.next() orelse "";
            try self.queries.put(
                try self.allocator.dupe(u8, key),
                try self.allocator.dupe(u8, value),
            );
        }
    }

    pub fn deinit(self: *HttpRequest) void {
        defer {
            self.raw_headers.deinit();
            self.params.deinit();
            self.queries.deinit();
        }
        var q_itr = self.queries.iterator();
        var p_itr = self.params.iterator();
        while (q_itr.next()) |entry| {
            _ = self.queries.remove(entry.key_ptr.*);
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }

        while (p_itr.next()) |entry| {
            _ = self.queries.remove(entry.key_ptr.*);
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
    }
};

const ResponseOption = struct {
    version: http.Version = .@"HTTP/1.1",
    reason: ?[]const u8 = null,
    transfer_encoding: ?Response.TransferEncoding = .none,
    extra_headers: ?HashMap = null,
    status: http.Status = .ok,
    keep_alive: bool = false,
};

pub const HttpResponse = struct {
    version: http.Version = .@"HTTP/1.1",
    response: *Response,
    allocator: Allocator,
    transfer_encoding: ?http.TransferEncoding = null,
    headers: ?HashMap = null,
    status: http.Status = .ok,
    body: ?[]u8 = null,
    keep_alive: bool = false,
    h: []http.Header = undefined,

    pub fn init(allocator: Allocator, request: *HttpRequest, buffer: []u8) !HttpResponse {
        var response = try allocator.create(Response);

        response.chunk_len = 0;
        response.send_buffer_start = 0;
        response.send_buffer = buffer;
        response.elide_body = false;
        response.send_buffer_end = 0;
        response.stream = request.request.server.connection.stream;

        return HttpResponse{
            .allocator = allocator,
            .response = response,
        };
    }

    pub fn stream_closed(self: *HttpResponse) bool {
        return isStreamClosed(self.response.stream);
    }

    fn isStreamClosed(stream: *std.net.Stream) bool {
        const tmp = "Checking body is closed";
        const closed = stream.write(std.mem.asBytes(&tmp)) catch |err| {
            std.debug.print("stream closed with err :{any}", .{err});
            return 0;
        };

        return closed == 0;
    }

    pub fn setHeaders(self: *HttpResponse, options: ResponseOption) !void {
        var headers = std.ArrayList(http.Header).init(self.allocator);
        defer headers.deinit();

        if (self.headers == null) {
            self.headers = HashMap.init(self.allocator);
            try headers.append(.{ .name = "Content-Type", .value = "text/plain" });
        }

        if (options.extra_headers) |header| {
            var h_itr = header.iterator();
            while (h_itr.next()) |h| {
                try headers.append(.{ .name = h.key_ptr.*, .value = h.value_ptr.* });
            }
        }

        if (options.transfer_encoding) |te| {
            self.response.transfer_encoding = te;
        }

        self.h = try headers.toOwnedSlice();

        var h = std.ArrayListUnmanaged(u8).initBuffer(self.response.send_buffer);

        h.fixedWriter().print(
            "{s} {d} {s}\r\n",
            .{
                @tagName(self.version),
                @intFromEnum(self.status),
                self.status.phrase() orelse "",
            },
        ) catch unreachable;

        switch (self.version) {
            .@"HTTP/1.0" => if (self.keep_alive) h.appendSliceAssumeCapacity("Connection: keep-alive\r\n"),
            .@"HTTP/1.1" => if (!self.keep_alive) h.appendSliceAssumeCapacity("Connection: close\r\n"),
        }

        switch (self.response.transfer_encoding) {
            .chunked => h.appendSliceAssumeCapacity("transfer-encoding: chunked\r\n"),
            .content_length => |len| {
                try h.fixedWriter().print("Content-Length: {d}\r\n", .{len});
            },
            else => {},
        }

        for (self.h) |val| {
            std.debug.assert(val.name.len != 0);
            h.appendSliceAssumeCapacity(val.name);
            h.appendSliceAssumeCapacity(": ");
            h.appendSliceAssumeCapacity(val.value);
            h.appendSliceAssumeCapacity("\r\n");
        }
        h.appendSliceAssumeCapacity("\r\n");

        self.response.send_buffer_end = h.items.len;
    }

    pub fn respond(self: *HttpResponse, content: []const u8) !void {
        try self.setHeaders(.{
            .transfer_encoding = .{ .content_length = content.len },
        });

        try self.response.writeAll(content);
        try self.response.end();
    }

    pub fn setBody(self: *HttpResponse, body: ?[]const u8) !void {
        if (self.body) |old_bold| {
            self.allocator.free(old_bold);
        }
        if (body) |content| {
            self.body = try self.allocator.alloc(u8, content.len);
            std.mem.copyForwards(u8, self.body.?, content);
        } else {
            self.body = null;
        }
    }

    pub fn getBody(self: *HttpResponse) ?[]const u8 {
        return if (self.body) |body| body else null;
    }

    pub fn deinit(self: *HttpResponse) void {
        if (self.headers != null) {
            var h_itr = self.headers.?.iterator();
            while (h_itr.next()) |hd| {
                if (self.headers.?.remove(hd.key_ptr.*)) {
                    self.allocator.free(hd.key_ptr.*);
                    self.allocator.free(hd.value_ptr.*);
                }
            }
            self.headers.?.deinit();
            self.headers = null;
        }

        if (self.body) |body| {
            self.allocator.free(body);
            self.body = null;
        }

        self.allocator.destroy(self.response);
    }
};

pub const Router = struct {
    allocator: Allocator,
    server: std.net.Server,
    ip: []const u8,
    port: u16,
    hostname: []const u8,
    routes: RouteList,
    log_level: LogLevel = .debug,
    logger: std.fs.File,
    http_server: ?*http.Server = null,
    thread_count: usize,
    dependencies: DependencyList,

    pub fn init(
        allocator: Allocator,
        ip: []const u8,
        port: u16,
        log_level: LogLevel,
        logger: ?std.fs.File,
        thread_count: usize,
    ) !Router {
        const address = try std.net.Address.parseIp(ip, port);
        const server = try address.listen(.{ .reuse_address = true });
        const hostname = try std.fmt.allocPrint(allocator, "http://{s}:{d}", .{ ip, port });
        var configuredThreadNumber: usize = thread_count;
        if (thread_count == 0) {
            configuredThreadNumber = Thread.getCpuCount() catch defaultNumberOfThread;
            if (configuredThreadNumber > defaultNumberOfThread) {
                configuredThreadNumber = configuredThreadNumber - 1;
            }
        }

        const stdout = logg: {
            if (logger) |lg| {
                break :logg lg;
            }
            break :logg std.io.getStdOut();
        };
        return Router{
            .ip = ip,
            .port = port,
            .allocator = allocator,
            .hostname = hostname,
            .server = server,
            .logger = stdout,
            .log_level = log_level,
            .routes = RouteList.init(allocator),
            .thread_count = configuredThreadNumber,
            .dependencies = DependencyList.init(allocator),
        };
    }

    pub fn deinit(self: *Router) void {
        self.allocator.free(self.hostname);
        var route_itr = self.routes.iterator();
        while (route_itr.next()) |route| {
            _ = self.routes.remove(route.key_ptr.*);
            self.allocator.free(route.key_ptr.*);
            route.value_ptr.deinit();
        }

        var dep_itr = self.dependencies.iterator();
        while (dep_itr.next()) |dep| {
            _ = self.dependencies.remove(dep.key_ptr.*);
            self.allocator.free(dep.key_ptr.*);
        }

        self.routes.deinit();
        self.dependencies.deinit();
        self.server.deinit();
    }

    pub fn get(self: *Router, path: []const u8, handler: HandlerFn) !void {
        return self.addRoute(.GET, path, handler);
    }

    pub fn put(self: *Router, path: []const u8, handler: HandlerFn) !void {
        return self.addRoute(.PUT, path, handler);
    }

    pub fn delete(self: *Router, path: []const u8, handler: HandlerFn) !void {
        return self.addRoute(.DELETE, path, handler);
    }

    pub fn patch(self: *Router, path: []const u8, handler: HandlerFn) !void {
        return self.addRoute(.PATCH, path, handler);
    }

    pub fn post(self: *Router, path: []const u8, handler: HandlerFn) !void {
        return self.addRoute(.POST, path, handler);
    }

    pub fn addRoute(self: *Router, method: http.Method, path: []const u8, handler: HandlerFn) !void {
        var route = Route.init(path, method, handler);
        const key = try route.get_key(self.allocator);
        defer self.allocator.free(key);
        const entry = try self.routes.getOrPut(key);
        if (!entry.found_existing) {
            entry.key_ptr.* = try self.allocator.dupe(u8, key);
            entry.value_ptr.* = route;
        }
    }

    pub fn addDependency(self: *Router, key: []const u8, dep: *anyopaque) !void {
        const entry = try self.dependencies.getOrPut(key);
        if (!entry.found_existing) {
            entry.key_ptr.* = key;
            entry.value_ptr.* = dep;
        }
    }

    pub fn log(self: *Router, level: LogLevel, comptime fmt: []const u8, args: anytype) !void {
        if (@intFromEnum(self.log_level) < @intFromEnum(level)) return;
        const timestamp = std.time.timestamp();
        const prefixed_fmt = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(prefixed_fmt);

        const log_fmt = switch (level) {
            .err => try std.fmt.allocPrint(self.allocator, "\x1b[31;1m[{any}]\x1b[0m : {s} -- {d}\n", .{ level, prefixed_fmt, timestamp }),
            .debug => try std.fmt.allocPrint(self.allocator, "\x1b[34;1m[{any}]\x1b[0m : {s} -- {d}\n", .{ level, prefixed_fmt, timestamp }),
            .info => try std.fmt.allocPrint(self.allocator, "\x1b[32;1m[{any}]\x1b[0m : {s} -- {d}\n", .{ level, prefixed_fmt, timestamp }),
            .warn => try std.fmt.allocPrint(self.allocator, "\x1b[33;1m[{any}]\x1b[0m {s} -- {d}\n", .{ level, prefixed_fmt, timestamp }),
        };
        defer self.allocator.free(log_fmt);
        _ = try self.logger.write(log_fmt);
    }

    pub fn listen(self: *Router) !void {
        try self.log(.info, "listening via :: {s}", .{self.hostname});
        if (self.thread_count > 1) return try self.concurrentListen();
        return try self.singleListen();
    }

    fn listRegisteredRoutes(self: *Router) !void {
        var routes_iterator = self.routes.iterator();
        try self.log(.debug, "Register route >", .{});

        while (routes_iterator.next()) |route| {
            try self.log(.debug, "\t> {any} {s}", .{
                route.value_ptr.method,
                route.value_ptr.path,
            });
        }
    }
    pub fn concurrentListen(self: *Router) !void {
        const worker = struct {
            fn worker(w: *WaitGroup, r: *Router) !void {
                var router: *Router = @constCast(r);

                var send_buffer: [4096]u8 = undefined;
                var read_buffer: [4096]u8 = undefined;

                while (true) {
                    router.process(&send_buffer, &read_buffer) catch |err| {
                        try router.log(.err, "ERROR ON self.process : {any} ", .{err});
                    };
                }
                w.finish();
                try router.log(.debug, "Thread finished ...", .{});
            }
        }.worker;

        var wg = WaitGroup{};
        wg.reset();

        try self.listRegisteredRoutes();
        var threads = try self.allocator.alloc(Thread, self.thread_count);
        defer self.allocator.free(threads);

        for (threads, 0..self.thread_count) |_, idx| {
            wg.start();
            threads[idx] = try spawn(.{ .allocator = self.allocator }, worker, .{ &wg, self });
        }

        wg.wait();
        try self.log(.debug, "All threads has started, waiting for completion", .{});
        for (threads[0..], 0..self.thread_count) |*t, idx| {
            t.join();
            try self.log(.debug, "Joined thread {d}", .{idx});
        }
    }

    fn singleListen(self: *Router) !void {
        try self.log(.info, "starting single threaded server", .{});

        try self.listRegisteredRoutes();
        var read_buffer: [4096]u8 = undefined;
        var send_buffer: [4096]u8 = undefined;
        while (true) {
            self.process(&send_buffer, &read_buffer) catch |err| {
                self.log(.err, "error occurred -?> {any}", .{err}) catch {};
            };
        }
    }

    fn process(self: *Router, response_header_buf: []u8, request_header_buf: []u8) !void {
        var conn = try self.server.accept();
        defer conn.stream.close();

        var http_server = http.Server.init(conn, request_header_buf);

        while (http_server.state == .ready) {
            const start = std.time.milliTimestamp();
            var request = http_server.receiveHead() catch |err| {
                self.log(.info, "closing connection : {any}", .{err}) catch {};
                return err;
            };
            const url = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ self.hostname, request.head.target });
            defer self.allocator.free(url);
            const uri = std.Uri.parse(url) catch |err| {
                self.log(.err, "error occurred while parsing url {s} - {any}", .{ url, err }) catch {};
                const error_response = try std.fmt.allocPrint(self.allocator, "{}", .{err});
                defer self.allocator.free(error_response);
                try request.respond(error_response, .{
                    .status = .bad_request,
                    .reason = "Unable to parse provided url",
                    .keep_alive = false,
                    .transfer_encoding = .none,
                });
                return err;
            };

            request.head = try http.Server.Request.Head.parse(request_header_buf);
            if (request.head.content_type == null) {
                request.head.content_type = "plain/text";
            }

            if (request.head.content_length == null) {
                request.head.content_length = 0;
            }

            self.log(.info, "incoming request to {s} with header {any}", .{
                request.head.target,
                request.head,
            }) catch {};

            const handler_key = try hash_key(self.allocator, request.head.method, uri.path.percent_encoded);
            defer self.allocator.free(handler_key);
            const found = self.routes.get(handler_key);
            if (found) |route| {
                var arena = std.heap.ArenaAllocator.init(self.allocator);
                defer arena.deinit();
                const allocator = arena.allocator();
                var hrequest = try HttpRequest.init(allocator, uri, route.path, &request);
                var hresponse = try HttpResponse.init(allocator, &hrequest, response_header_buf);
                defer {
                    hrequest.deinit();
                    hresponse.deinit();
                }

                route.handlerFn(allocator, RContext{ .request = &hrequest, .response = &hresponse, .deps = &self.dependencies }) catch |err| {
                    try self.log(.debug, "ERROR route.handler: {any}", .{err});
                    try request.respond("{{ \"error\": \"route can't be handle\"}}", .{ .status = .internal_server_error });
                    return err;
                };

                if (hresponse.body) |body| {
                    hresponse.respond(body) catch |err| {
                        self.log(.debug, "ERROR hresponse.respond: {any}", .{err}) catch {};
                        return err;
                    };
                } else {
                    hresponse.response.end() catch |err| {
                        self.log(.debug, "ERROR hresponse.response.end: {any}", .{err}) catch {};
                        return err;
                    };
                }
            } else {
                try self.log(.err, "Unsupported route {any} - {s}", .{ request.head.method, handler_key });
                request.respond(
                    "not found",
                    .{ .status = .not_found },
                ) catch |err| {
                    try self.log(.debug, "ERROR: {any}\n", .{err});
                    return err;
                };
            }
            const finish = std.time.milliTimestamp();
            try self.log(.info, "request served in: {d}ms", .{(finish - start)});
        }
    }
};
