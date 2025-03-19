const std = @import("std");
const root = @import("root.zig");

const InputType = enum { string, file };

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    const input_type = try get_input_type(args);

    const base64 = root.Base64.init();

    switch (input_type) {
        InputType.string => {
            const result = try base64.encode(alloc, args[1]);
            defer alloc.free(result);
            std.debug.print("{s}\n", .{result});
        },
        else => {},
    }
}

fn get_input_type(args: [][:0]u8) !InputType {
    if (args.len == 2) {
        return InputType.string;
    } else if (args.len == 3) {
        if (std.mem.eql(u8, args[1], "--string") or std.mem.eql(u8, args[1], "-s")) {
            return InputType.string;
        } else if (std.mem.eql(u8, args[1], "--file") or std.mem.eql(u8, args[1], "-f")) {
            // return InputType.file;
            return error.NotImplemented;
        } else {
            std.debug.print("Invalid argument! Expected input type, received {s}\n", .{args[1]});
            return error.InvalidArgument;
        }
    }
    return error.InvalidArgumentCount;
}
