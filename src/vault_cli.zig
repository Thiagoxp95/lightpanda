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

//! `lightpanda vault <add|list|rm|import-bitwarden>`: edits a workspace's
//! vault from the terminal. Secrets come in on stdin and never go out.

const std = @import("std");
const lp = @import("lightpanda");

const App = @import("App.zig");
const Config = @import("Config.zig");
const Vault = @import("Vault.zig");
const Workspace = @import("Workspace.zig");

const Allocator = std.mem.Allocator;
const Options = @FieldType(Config.Mode, "vault");

pub const usage_hint = "usage: vault add <name> --host <HOST> --username <USER> | list | rm <name> | import-bitwarden <export.json>";

/// `error.Usage` means the arguments made no sense and the help should print.
pub fn run(allocator: Allocator, opts: Options) !void {
    const args = opts.args.items;
    if (args.len == 0) return error.Usage;

    var stdout_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(lp.io, &stdout_buf);
    const out = &stdout.interface;
    defer out.flush() catch {};

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    const ws_name = opts.workspace orelse return fail("vault needs --workspace <NAME> or LIGHTPANDA_WORKSPACE", .{});
    const app_dir = try App.getAppDataDir(allocator, "lightpanda");
    defer allocator.free(app_dir);
    const ws = try Workspace.open(allocator, app_dir, ws_name);
    defer ws.deinit(allocator);

    var vault = (try Vault.load(allocator, ws)) orelse Vault.empty(allocator);
    defer vault.deinit();

    const sub = args[0];
    if (std.mem.eql(u8, sub, "list")) {
        if (args.len != 1) return error.Usage;
        if (vault.entries.items.len == 0) {
            try out.print("vault \"{s}\" is empty\n", .{ws.name});
            return;
        }
        for (vault.entries.items) |entry| {
            try out.print("{s}\n  hosts: {s}\n  username: {s}\n  totp: {s}\n", .{
                entry.name,
                if (entry.hosts.len == 0) "(none)" else try std.mem.join(scratch, ", ", entry.hosts),
                entry.username,
                if (entry.totp_secret != null) "yes" else "no",
            });
        }
        return;
    }
    if (std.mem.eql(u8, sub, "add")) {
        if (args.len != 2) return error.Usage;
        const name = args[1];
        if (!Vault.validName(name)) return fail("\"{s}\": a vault entry name is 1 to {d} characters of a-z, 0-9 or '_'", .{ name, Vault.max_name_len });
        if (opts.host.items.len == 0) return fail("vault add needs at least one --host", .{});
        const username = opts.username orelse return fail("vault add needs --username", .{});

        const secrets = try readSecrets(allocator, opts.totp_stdin);
        defer secrets.deinit(allocator);
        if (secrets.password.len == 0) return fail("no password on stdin", .{});
        if (opts.totp_stdin and secrets.totp.?.len == 0) return fail("--totp-stdin but no second line on stdin", .{});

        try vault.put(.{
            .name = name,
            .hosts = opts.host.items,
            .username = username,
            .password = secrets.password,
            .totp_secret = secrets.totp,
        });
        try vault.save(allocator, ws);
        const up = upper(name);
        try out.print("added \"{s}\" to vault \"{s}\": $LP_{s}_USERNAME, $LP_{s}_PASSWORD{s}{s}\n", .{
            name, ws.name, up, up, if (secrets.totp != null) ", $LP_" else "", if (secrets.totp != null) try std.mem.concat(scratch, u8, &.{ up, "_TOTP" }) else "",
        });
        return;
    }
    if (std.mem.eql(u8, sub, "rm")) {
        if (args.len != 2) return error.Usage;
        if (vault.remove(args[1])) {
            try vault.save(allocator, ws);
            try out.print("removed \"{s}\" from vault \"{s}\"\n", .{ args[1], ws.name });
        } else {
            try out.print("vault \"{s}\" has no entry \"{s}\"; nothing to remove\n", .{ ws.name, args[1] });
        }
        return;
    }
    if (std.mem.eql(u8, sub, "import-bitwarden")) {
        if (args.len != 2) return error.Usage;
        const json_text = std.Io.Dir.cwd().readFileAlloc(lp.io, args[1], scratch, .limited(64 * 1024 * 1024)) catch |err| {
            return fail("read {s}: {s}", .{ args[1], @errorName(err) });
        };
        defer std.crypto.secureZero(u8, json_text);
        const count = vault.importBitwarden(scratch, json_text, opts.folder) catch |err| switch (err) {
            error.EncryptedExport => return fail("{s} is an encrypted export; export as unencrypted JSON", .{args[1]}),
            error.FolderNotFound => return fail("no Bitwarden folder named \"{s}\"", .{opts.folder.?}),
            error.NotABitwardenExport => return fail("{s} is not a Bitwarden JSON export", .{args[1]}),
            else => return err,
        };
        try vault.save(allocator, ws);
        try out.print("imported {d} login(s) into vault \"{s}\" ({d} without a password skipped)\n", .{ count.imported, ws.name, count.skipped });
        return;
    }
    return error.Usage;
}

fn fail(comptime fmt: []const u8, args: anytype) error{VaultCommandFailed} {
    std.debug.print("error: " ++ fmt ++ "\n", args);
    return error.VaultCommandFailed;
}

/// Uppercase copy for messages, in a fixed buffer because names are short.
fn upper(name: []const u8) []const u8 {
    const S = struct {
        var buf: [Vault.max_name_len]u8 = undefined;
    };
    return std.ascii.upperString(&S.buf, name);
}

const Secrets = struct {
    password: []u8,
    totp: ?[]u8,

    fn deinit(self: Secrets, allocator: Allocator) void {
        std.crypto.secureZero(u8, self.password);
        allocator.free(self.password);
        if (self.totp) |t| {
            std.crypto.secureZero(u8, t);
            allocator.free(t);
        }
    }
};

/// One line per secret on stdin: the password, then the TOTP secret when
/// asked. A terminal gets a prompt and no echo; a pipe is read as is.
fn readSecrets(allocator: Allocator, want_totp: bool) !Secrets {
    const stdin = std.Io.File.stdin();
    const tty = stdin.isTty(lp.io) catch false;

    var saved: std.c.termios = undefined;
    if (tty and std.c.tcgetattr(stdin.handle, &saved) == 0) {
        var quiet = saved;
        quiet.lflag.ECHO = false;
        _ = std.c.tcsetattr(stdin.handle, .NOW, &quiet);
    }
    defer if (tty) {
        _ = std.c.tcsetattr(stdin.handle, .NOW, &saved);
    };

    var buf: [4096]u8 = undefined;
    var reader = stdin.readerStreaming(lp.io, &buf);

    if (tty) std.debug.print("Password: ", .{});
    const password = try readLine(allocator, &reader.interface);
    errdefer allocator.free(password);
    if (tty) std.debug.print("\n", .{});

    var totp: ?[]u8 = null;
    if (want_totp) {
        if (tty) std.debug.print("TOTP secret (base32): ", .{});
        totp = try readLine(allocator, &reader.interface);
        if (tty) std.debug.print("\n", .{});
    }
    return .{ .password = password, .totp = totp };
}

/// A copy of the next line; the reader's buffer is zeroed behind it.
fn readLine(allocator: Allocator, reader: *std.Io.Reader) ![]u8 {
    const line = (try reader.takeDelimiter('\n')) orelse return allocator.dupe(u8, "");
    defer std.crypto.secureZero(u8, line);
    return allocator.dupe(u8, std.mem.trimEnd(u8, line, "\r"));
}
