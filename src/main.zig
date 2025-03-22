const std = @import("std");
const root = @import("root.zig");

const InputType = enum { string, file };
const OperationType = enum { encode, decode };

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len == 1) {
        const stdout_file = std.io.getStdOut().writer();
        var bw = std.io.bufferedWriter(stdout_file);
        const stdout = bw.writer();
        try stdout.print("zencode v0.0.0\n", .{}); //TODO: get version from build.zig?
        try stdout.print("Format: zencode [--string|-s|] ", .{});
        try stdout.print("[--file|-f] [--encode|-e] [--decode|-d] input_string|file_path\n", .{});
        try bw.flush();
        return;
    }

    const input_type = try getInputType(args);
    const operation_type = try getOperationType(args);

    const base64 = root.Base64.init();

    switch (operation_type) {
        OperationType.encode => {
            switch (input_type) {
                InputType.string => {
                    const result = try base64.encode(alloc, args[args.len - 1]);
                    defer alloc.free(result);
                    std.debug.print("{s}\n", .{result});
                },
                else => {},
            }
        },
        OperationType.decode => {
            switch (input_type) {
                InputType.string => {
                    const result = try base64.decode(alloc, args[args.len - 1]);
                    defer alloc.free(result);
                    std.debug.print("{s}\n", .{result});
                },
                else => {},
            }
        },
    }
}

fn getInputType(args: [][:0]u8) !InputType {
    var ret = InputType.string;
    if (args.len > 2) {
        for (1..args.len) |i| {
            if (arg_compare(args[i], [_][]const u8{ "--string", "-s" })) {
                ret = InputType.string;
            } else if (arg_compare(args[i], [_][]const u8{ "--file", "-f" })) {
                ret = InputType.file;
                return error.NotImplemented;
            }
        }
    }
    return ret;
}

fn arg_compare(argument: []const u8, words: [2][]const u8) bool {
    for (words) |input| {
        if (std.mem.eql(u8, input, argument)) {
            return true;
        }
    }
    return false;
}

fn getOperationType(args: [][:0]u8) !OperationType {
    var ret: OperationType = OperationType.encode;
    if (args.len > 2) {
        for (1..args.len) |i| {
            if (arg_compare(args[i], [_][]const u8{ "--encode", "-e" })) {
                ret = OperationType.encode;
            } else if (arg_compare(args[i], [_][]const u8{ "--decode", "-d" })) {
                ret = OperationType.decode;
            }
        }
    }
    return ret;
}
