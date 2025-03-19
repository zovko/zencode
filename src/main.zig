const std = @import("std");
const root = @import("root.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const base64 = root.Base64.init();
    const input_string = "Gami";
    const result = try base64.encode(alloc, input_string);
    std.debug.print("test encode string \"{s}\": {s}\n", .{ input_string, result });
}
