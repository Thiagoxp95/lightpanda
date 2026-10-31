// Copyright (C) 2023-2026  Lightpanda (Selecy SAS)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! A named, persistent browsing identity: `<app data dir>/workspaces/<name>`
//! holds the state (today the cookie jar) that survives between runs, so two
//! workspaces never share a sign-in.

const std = @import("std");
const builtin = @import("builtin");
const lp = @import("lightpanda");

const Allocator = std.mem.Allocator;
const File = std.Io.File;

const Workspace = @This();

name: []const u8,
dir: []const u8,

/// Owner-only, for files and directories holding credentials.
pub const private_file: File.Permissions = if (builtin.os.tag == .windows) .default_file else @fromBackingInt(@intCast(0o600));
pub const private_dir: File.Permissions = if (builtin.os.tag == .windows) .default_dir else @fromBackingInt(@intCast(0o700));

pub const max_name_len = 64;

/// `[a-z0-9_-]{1,64}`: nothing that can climb out of the workspaces directory.
pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) {
        return false;
    }
    for (name) |c| {
        switch (c) {
            'a'...'z', '0'...'9', '_', '-' => {},
            else => return false,
        }
    }
    return true;
}

/// Resolves `name` under `app_dir` and creates the directory, owner-only, on
/// first use. `name` must already be `validName`.
pub fn open(allocator: Allocator, app_dir: []const u8, name: []const u8) !Workspace {
    std.debug.assert(validName(name));

    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    const dir = try std.fs.path.join(allocator, &.{ app_dir, "workspaces", name });
    errdefer allocator.free(dir);

    // The parent too: it is just as private, and holds every other workspace.
    const parent = std.fs.path.dirname(dir).?;
    _ = try std.Io.Dir.cwd().createDirPathStatus(lp.io, parent, private_dir);
    _ = try std.Io.Dir.cwd().createDirPathStatus(lp.io, dir, private_dir);
    return .{ .name = owned_name, .dir = dir };
}

pub fn deinit(self: Workspace, allocator: Allocator) void {
    allocator.free(self.name);
    allocator.free(self.dir);
}

pub fn cookiesPath(self: Workspace, allocator: Allocator) ![]u8 {
    return std.fs.path.join(allocator, &.{ self.dir, "cookies.json" });
}

test "Workspace: validName" {
    try std.testing.expectEqual(true, validName("personal"));
    try std.testing.expectEqual(true, validName("a"));
    try std.testing.expectEqual(true, validName("tedy_2-b"));
    const x: [max_name_len + 1]u8 = @splat('x');
    try std.testing.expectEqual(true, validName(x[0..max_name_len]));

    try std.testing.expectEqual(false, validName(""));
    try std.testing.expectEqual(false, validName(&x));
    try std.testing.expectEqual(false, validName(".."));
    try std.testing.expectEqual(false, validName("../x"));
    try std.testing.expectEqual(false, validName("a/b"));
    try std.testing.expectEqual(false, validName("a\\b"));
    try std.testing.expectEqual(false, validName("Upper"));
    try std.testing.expectEqual(false, validName("sp ace"));
    try std.testing.expectEqual(false, validName("nul\x00"));
    try std.testing.expectEqual(false, validName("é"));
}

test "Workspace: open creates a private directory, cookiesPath lives in it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realPathFileAlloc(lp.io, ".", std.testing.allocator);
    defer std.testing.allocator.free(root);

    const ws = try open(std.testing.allocator, root, "e2e");
    defer ws.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("e2e", ws.name);
    const expected = try std.fs.path.join(std.testing.allocator, &.{ root, "workspaces", "e2e" });
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, ws.dir);

    const cookies = try ws.cookiesPath(std.testing.allocator);
    defer std.testing.allocator.free(cookies);
    try std.testing.expectEqual(true, std.mem.endsWith(u8, cookies, "e2e/cookies.json"));

    if (builtin.os.tag != .windows) {
        const stat = try tmp.dir.statFile(lp.io, "workspaces/e2e", .{});
        try std.testing.expectEqual(@as(u32, 0o700), @as(u32, @backingInt(stat.permissions)) & 0o777);
    }

    // Opening again is a no-op.
    const again = try open(std.testing.allocator, root, "e2e");
    again.deinit(std.testing.allocator);
}
