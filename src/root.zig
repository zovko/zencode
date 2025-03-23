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

        const ret = try alloc.alloc(u8, try calculate_encode_len(input));
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

    fn table_index(self: Base64, input: u8) u8 {
        return @intCast(std.mem.indexOfScalar(u8, self.table, input).?);
    }

    fn calculate_decode_len(input: []const u8) !usize {
        if (input.len < 4) {
            return 3;
        }

        return try std.math.divFloor(usize, input.len, 4) * 3;
    }

    fn full_chunk_decode(self: Base64, input_string: []const u8, output_string: []u8, output_index: usize, input_index: usize) void {
        output_string[output_index + 0] = (self.table_index(input_string[input_index]) << 2) |
            ((self.table_index(input_string[input_index + 1]) & 0b0011_0000) >> 4);

        output_string[output_index + 1] = ((self.table_index(input_string[input_index + 1]) & 0b0000_1111) << 4) |
            ((self.table_index(input_string[input_index + 2]) & 0b0011_1100) >> 2);

        output_string[output_index + 2] = ((self.table_index(input_string[input_index + 2]) & 0b0000_0011) << 6) |
            ((self.table_index(input_string[input_index + 3])));
    }

    pub fn decode(self: Base64, alloc: std.mem.Allocator, input_string: []const u8) ![]u8 {
        if (input_string.len == 0) {
            return "";
        }

        const pad_char_count = std.mem.count(u8, input_string, "=");
        const result = try alloc.alloc(u8, try calculate_decode_len(input_string));
        @memset(result, 0);

        var input_index: usize = 0;
        var output_index: usize = 0;

        while (input_index < (input_string.len - 4)) {
            full_chunk_decode(self, input_string, result, output_index, input_index);
            output_index += 3;
            input_index += 4;
        }

        if (pad_char_count == 1) {
            result[output_index + 0] = (self.table_index(input_string[input_index]) << 2) |
                ((self.table_index(input_string[input_index + 1]) & 0b0011_0000) >> 4);

            result[output_index + 1] = ((self.table_index(input_string[input_index + 1]) & 0b0000_1111) << 4) |
                ((self.table_index(input_string[input_index + 2]) & 0b0011_1100) >> 2);

            result[output_index + 2] = self.table_index(input_string[input_index + 2]) << 6;
        } else if (pad_char_count == 2) {
            result[output_index + 0] = (self.table_index(input_string[input_index]) << 2) |
                ((self.table_index(input_string[input_index + 1]) & 0b0011_0000) >> 4);

            result[output_index + 1] = ((self.table_index(input_string[input_index + 1]) & 0b0000_1111) << 4);
        } else if (pad_char_count == 0) {
            full_chunk_decode(self, input_string, result, output_index, input_index);
        }

        return result;
    }
};

test "test encode len calc" {
    try testing.expect(try Base64.calculate_encode_len("") == 0);
    try testing.expect(try Base64.calculate_encode_len("f") == 4);
    try testing.expect(try Base64.calculate_encode_len("fo") == 4);
    try testing.expect(try Base64.calculate_encode_len("foo") == 4);
    try testing.expect(try Base64.calculate_encode_len("foob") == 8);
    try testing.expect(try Base64.calculate_encode_len("fooba") == 8);
    try testing.expect(try Base64.calculate_encode_len("foobar") == 8);
}

test "test encoding" {
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

fn string_size(str: []const u8) usize {
    var len = str.len;
    while (len != 0 and str[len - 1] == 0) {
        len -= 1;
    }
    return len;
}

fn testDecode(alloc: std.mem.Allocator, base64: Base64, input: []const u8, compare: []const u8) !void {
    const dcd = try base64.decode(alloc, input);
    defer alloc.free(dcd);
    if (testing.expect(std.mem.eql(u8, dcd[0..string_size(dcd)], compare))) {} else |err| {
        std.debug.print("str=\"{s}\" len={d} strlen={d}\n", .{ dcd, dcd.len, string_size(dcd) });
        return err;
    }
}

test "test decode" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    const base64 = Base64.init();

    // try testDecode(alloc, base64, "", "");
    try testDecode(alloc, base64, "Zg==", "f");
    try testDecode(alloc, base64, "Zm8=", "fo");
    try testDecode(alloc, base64, "Zm9v", "foo");
    try testDecode(alloc, base64, "Zm9vYg==", "foob");
    try testDecode(alloc, base64, "Zm9vYmE=", "fooba");
    try testDecode(alloc, base64, "Zm9vYmFy", "foobar");
}
