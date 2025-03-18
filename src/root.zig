const std = @import("std");
const testing = std.testing;

pub const Base64 = struct {
    table: *const [64]u8 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    deliminator: u8 = '=',

    pub fn init() Base64 {
        return Base64{};
    }

    fn calculate_encode_len(input: []const u8) !usize {
        if (input.len == 0) {
            return 0;
        }

        if (input.len < 3) {
            return 4;
        }

        return (try std.math.divCeil(usize, input.len, 3) * 4);
    }

    pub fn encode(self: Base64, alloc: std.mem.Allocator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return "";
        }

        const ret: []u8 = try alloc.alloc(u8, try calculate_encode_len(input));
        var buf = [3]u8{ 0, 0, 0 };
        var buf_count: u8 = 0;
        var ret_index: usize = 0;

        for (input, 0..) |_, i| {
            buf[buf_count] = input[i];
            buf_count += 1;

            if (buf_count == 3) {
                ret[ret_index] = self.table[buf[0] >> 2];
                ret[ret_index + 1] = self.table[((buf[0] & 0b11) << 4) + (buf[1] >> 4)];
                ret[ret_index + 2] = self.table[((buf[1] & 0b1111) << 2) + (buf[2] >> 6)];
                ret[ret_index + 3] = self.table[buf[2] & 0b0011_1111];
                ret_index += 4;
                buf_count = 0;
            }
        }

        if (buf_count == 1) {
            ret[ret_index] = self.table[buf[0] >> 2];
            ret[ret_index + 1] = self.table[(buf[0] & 0b11) << 4];
            ret[ret_index + 2] = self.deliminator;
            ret[ret_index + 3] = self.deliminator;
        }

        if (buf_count == 2) {
            ret[ret_index] = self.table[buf[0] >> 2];
            ret[ret_index + 1] = self.table[((buf[0] & 0b11) << 4) + (buf[1] >> 4)];
            ret[ret_index + 2] = self.table[((buf[1] & 0b1111) << 2)];
            ret[ret_index + 3] = self.deliminator;
        }

        return ret;
    }
};

test "test len calc" {
    try testing.expect(try Base64.calculate_encode_len("") == 0);
    try testing.expect(try Base64.calculate_encode_len("f") == 4);
    try testing.expect(try Base64.calculate_encode_len("fo") == 4);
    try testing.expect(try Base64.calculate_encode_len("foo") == 4);
    try testing.expect(try Base64.calculate_encode_len("foob") == 8);
    try testing.expect(try Base64.calculate_encode_len("fooba") == 8);
    try testing.expect(try Base64.calculate_encode_len("foobar") == 8);
}

test "test vectors" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const base64 = Base64.init();
    try testing.expect(std.mem.eql(u8, try base64.encode(alloc, ""), ""));
    try testing.expect(std.mem.eql(u8, try base64.encode(alloc, "f"), "Zg=="));
    try testing.expect(std.mem.eql(u8, try base64.encode(alloc, "fo"), "Zm8="));
    try testing.expect(std.mem.eql(u8, try base64.encode(alloc, "foo"), "Zm9v"));
    try testing.expect(std.mem.eql(u8, try base64.encode(alloc, "foob"), "Zm9vYg=="));
    try testing.expect(std.mem.eql(u8, try base64.encode(alloc, "fooba"), "Zm9vYmE="));
    try testing.expect(std.mem.eql(u8, try base64.encode(alloc, "foobar"), "Zm9vYmFy"));
}
