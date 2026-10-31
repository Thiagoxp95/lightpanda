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

//! A workspace's credentials: login entries the model reaches only through
//! `$LP_<NAME>_<FIELD>` placeholders, each bound to the hosts it may be sent
//! to. On disk `<workspace>/vault.lpv` is XChaCha20-Poly1305 over the JSON
//! entries, keyed by 32 random bytes kept in the macOS login Keychain (a
//! `vault.key` file elsewhere) and authenticated with the workspace name, so
//! a vault copied into another workspace does not open.

const std = @import("std");
const builtin = @import("builtin");
const lp = @import("lightpanda");

const Workspace = @import("Workspace.zig");
const keychain = if (builtin.os.tag == .macos) @import("sys/keychain.zig") else void;

const Allocator = std.mem.Allocator;
const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const log = lp.log;

const Vault = @This();

pub const file_name = "vault.lpv";
pub const key_file_name = "vault.key";
pub const keychain_service = "lightpanda-vault";
pub const magic = "LPV1";
pub const max_name_len = 32;
const max_file_len = 16 * 1024 * 1024;

pub const Field = enum {
    username,
    password,
    totp,

    fn suffix(self: Field) []const u8 {
        return switch (self) {
            .username => "_USERNAME",
            .password => "_PASSWORD",
            .totp => "_TOTP",
        };
    }
};

pub const Entry = struct {
    name: []const u8,
    hosts: []const []const u8,
    username: []const u8,
    password: []const u8,
    totp_secret: ?[]const u8 = null,

    pub fn matchesHost(self: Entry, host: []const u8) bool {
        for (self.hosts) |h| {
            if (hostMatches(h, host)) return true;
        }
        return false;
    }
};

/// `$LP_<NAME>_<FIELD>` split back into the entry it names and the field.
pub const Placeholder = struct {
    entry: []const u8,
    field: Field,
};

pub const Lookup = union(enum) {
    none,
    value: []const u8,
    /// The entry exists but is not bound to the page's host, or no page is
    /// loaded; the value stays in the vault.
    host_mismatch: *const Entry,
};

arena: std.heap.ArenaAllocator,
entries: std.ArrayList(Entry) = .empty,

pub fn empty(allocator: Allocator) Vault {
    return .{ .arena = .init(allocator) };
}

/// Zeroes every secret before the arena goes.
pub fn deinit(self: *Vault) void {
    for (self.entries.items) |entry| wipe(entry);
    self.arena.deinit();
}

fn wipe(entry: Entry) void {
    std.crypto.secureZero(u8, @constCast(entry.password));
    std.crypto.secureZero(u8, @constCast(entry.username));
    if (entry.totp_secret) |s| std.crypto.secureZero(u8, @constCast(s));
}

/// `[a-z0-9_]{1,32}`: uppercased it is the middle of the placeholder.
pub fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len) return false;
    for (name) |c| switch (c) {
        'a'...'z', '0'...'9', '_' => {},
        else => return false,
    };
    return true;
}

pub fn find(self: *const Vault, name: []const u8) ?*const Entry {
    for (self.entries.items) |*entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry;
    }
    return null;
}

/// The entry bound to `host`, the first one when several are.
pub fn forHost(self: *const Vault, host: []const u8) ?*const Entry {
    for (self.entries.items) |*entry| {
        if (entry.matchesHost(host)) return entry;
    }
    return null;
}

/// Copies `entry` in, replacing any entry with the same name.
pub fn put(self: *Vault, entry: Entry) error{ OutOfMemory, InvalidName }!void {
    if (!validName(entry.name)) return error.InvalidName;
    const aa = self.arena.allocator();
    const hosts = try aa.alloc([]const u8, entry.hosts.len);
    for (entry.hosts, hosts) |src, *dst| dst.* = try lowerDupe(aa, src);
    const owned: Entry = .{
        .name = try aa.dupe(u8, entry.name),
        .hosts = hosts,
        .username = try aa.dupe(u8, entry.username),
        .password = try aa.dupe(u8, entry.password),
        .totp_secret = if (entry.totp_secret) |s| try aa.dupe(u8, s) else null,
    };
    for (self.entries.items) |*existing| {
        if (std.mem.eql(u8, existing.name, entry.name)) {
            wipe(existing.*);
            existing.* = owned;
            return;
        }
    }
    try self.entries.append(aa, owned);
}

pub fn remove(self: *Vault, name: []const u8) bool {
    for (self.entries.items, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name)) {
            wipe(entry);
            _ = self.entries.orderedRemove(i);
            return true;
        }
    }
    return false;
}

/// `pattern` is an entry host; `host` matches when it is that host or a
/// subdomain of it. `evil-example.com` and `example.com.evil.net` do not.
pub fn hostMatches(pattern: []const u8, host: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(pattern, host)) return true;
    if (host.len <= pattern.len + 1) return false;
    const dot = host.len - pattern.len - 1;
    return host[dot] == '.' and std.ascii.eqlIgnoreCase(host[dot + 1 ..], pattern);
}

/// `buf` receives the lowercased entry name the result points into.
pub fn parsePlaceholder(var_name: []const u8, buf: *[max_name_len]u8) ?Placeholder {
    if (!std.mem.startsWith(u8, var_name, "LP_")) return null;
    const rest = var_name["LP_".len..];
    inline for (comptime std.enums.values(Field)) |field| {
        const suffix = comptime field.suffix();
        if (rest.len > suffix.len and std.mem.endsWith(u8, rest, suffix)) {
            const upper = rest[0 .. rest.len - suffix.len];
            if (upper.len > max_name_len) return null;
            for (upper) |c| switch (c) {
                'A'...'Z', '0'...'9', '_' => {},
                else => return null,
            };
            return .{ .entry = std.ascii.lowerString(buf, upper), .field = field };
        }
    }
    return null;
}

pub fn placeholderName(arena: Allocator, entry_name: []const u8, field: Field) error{OutOfMemory}![]const u8 {
    const name = try arena.print("LP_{s}{s}", .{ entry_name, field.suffix() });
    _ = std.ascii.upperString(name, name);
    return name;
}

/// Resolves a placeholder for a page on `host`. `null` host means no page is
/// loaded, which never matches: a vault value only leaves for its own site.
pub fn lookup(self: *const Vault, arena: Allocator, var_name: []const u8, host: ?[]const u8) error{OutOfMemory}!Lookup {
    var buf: [max_name_len]u8 = undefined;
    const ph = parsePlaceholder(var_name, &buf) orelse return .none;
    const entry = self.find(ph.entry) orelse return .none;
    if (ph.field == .totp and entry.totp_secret == null) return .none;
    const h = host orelse return .{ .host_mismatch = entry };
    if (!entry.matchesHost(h)) return .{ .host_mismatch = entry };
    return .{ .value = try fieldValue(arena, entry, ph.field) };
}

/// The value with no host check, for scrubbing recordings: a value that
/// must never land in a file is found whatever page produced it.
pub fn unbound(self: *const Vault, arena: Allocator, var_name: []const u8) error{OutOfMemory}!?[]const u8 {
    var buf: [max_name_len]u8 = undefined;
    const ph = parsePlaceholder(var_name, &buf) orelse return null;
    const entry = self.find(ph.entry) orelse return null;
    if (ph.field == .totp and entry.totp_secret == null) return null;
    return try fieldValue(arena, entry, ph.field);
}

fn fieldValue(arena: Allocator, entry: *const Entry, field: Field) error{OutOfMemory}![]const u8 {
    return switch (field) {
        .username => entry.username,
        .password => entry.password,
        .totp => blk: {
            const now: u64 = @intCast(std.Io.Timestamp.now(lp.io, .real).toSeconds());
            const code = try arena.alloc(u8, 6);
            totpCode(arena, entry.totp_secret.?, now, code[0..6]) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.InvalidBase32 => {
                    log.warn(.app, "vault totp secret not base32", .{ .entry = entry.name });
                    break :blk "";
                },
            };
            break :blk code;
        },
    };
}

/// Every placeholder the vault answers, for the names the model may list.
pub fn names(self: *const Vault, arena: Allocator) error{OutOfMemory}![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    for (self.entries.items) |entry| {
        try out.append(arena, try placeholderName(arena, entry.name, .username));
        try out.append(arena, try placeholderName(arena, entry.name, .password));
        if (entry.totp_secret != null) try out.append(arena, try placeholderName(arena, entry.name, .totp));
    }
    return out.toOwnedSlice(arena);
}

// ---- TOTP (RFC 6238, SHA-1, 30 s, 6 digits)

pub fn totpCode(arena: Allocator, base32_secret: []const u8, unix_seconds: u64, out: *[6]u8) error{ OutOfMemory, InvalidBase32 }!void {
    const secret = try base32Decode(arena, base32_secret);
    defer std.crypto.secureZero(u8, secret);
    const counter = unix_seconds / 30;
    var msg: [8]u8 = undefined;
    std.mem.writeInt(u64, &msg, counter, .big);
    var mac: [20]u8 = undefined;
    std.crypto.auth.hmac.HmacSha1.create(&mac, &msg, secret);
    const offset = mac[19] & 0x0f;
    const bin = std.mem.readInt(u32, mac[offset..][0..4], .big) & 0x7fff_ffff;
    _ = std.fmt.bufPrint(out, "{d:0>6}", .{bin % 1_000_000}) catch unreachable;
}

/// RFC 4648 base32, case-insensitive; padding, spaces and dashes ignored.
pub fn base32Decode(arena: Allocator, text: []const u8) error{ OutOfMemory, InvalidBase32 }![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var acc: u32 = 0;
    var bits: u5 = 0;
    for (text) |c| {
        const v: u32 = switch (c) {
            'A'...'Z' => c - 'A',
            'a'...'z' => c - 'a',
            '2'...'7' => c - '2' + 26,
            '=', ' ', '-' => continue,
            else => return error.InvalidBase32,
        };
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            try out.append(arena, @intCast((acc >> bits) & 0xff));
        }
    }
    if (out.items.len == 0) return error.InvalidBase32;
    return out.toOwnedSlice(arena);
}

// ---- On disk

const Json = struct { entries: []const Entry };

fn associatedData(workspace_name: []const u8, buf: *[magic.len + Workspace.max_name_len]u8) []const u8 {
    @memcpy(buf[0..magic.len], magic);
    @memcpy(buf[magic.len..][0..workspace_name.len], workspace_name);
    return buf[0 .. magic.len + workspace_name.len];
}

/// `magic | nonce | ciphertext | tag`, bound to `workspace_name`.
pub fn encrypt(self: *const Vault, allocator: Allocator, key: *const [Aead.key_length]u8, workspace_name: []const u8) ![]u8 {
    const plain = try std.json.Stringify.valueAlloc(allocator, Json{ .entries = self.entries.items }, .{});
    defer {
        std.crypto.secureZero(u8, plain);
        allocator.free(plain);
    }
    const out = try allocator.alloc(u8, magic.len + Aead.nonce_length + plain.len + Aead.tag_length);
    errdefer allocator.free(out);
    @memcpy(out[0..magic.len], magic);
    const nonce = out[magic.len..][0..Aead.nonce_length];
    try lp.io.randomSecure(nonce);
    const cipher = out[magic.len + Aead.nonce_length ..][0..plain.len];
    const tag = out[out.len - Aead.tag_length ..][0..Aead.tag_length];
    var ad_buf: [magic.len + Workspace.max_name_len]u8 = undefined;
    Aead.encrypt(cipher, tag, plain, associatedData(workspace_name, &ad_buf), nonce.*, key.*);
    return out;
}

pub fn decrypt(allocator: Allocator, bytes: []const u8, key: *const [Aead.key_length]u8, workspace_name: []const u8) !Vault {
    const header = magic.len + Aead.nonce_length;
    if (bytes.len < header + Aead.tag_length or !std.mem.eql(u8, bytes[0..magic.len], magic)) return error.NotAVault;
    const nonce = bytes[magic.len..][0..Aead.nonce_length];
    const cipher = bytes[header .. bytes.len - Aead.tag_length];
    const tag = bytes[bytes.len - Aead.tag_length ..][0..Aead.tag_length];

    var vault: Vault = .empty(allocator);
    errdefer vault.deinit();
    const aa = vault.arena.allocator();
    const plain = try aa.alloc(u8, cipher.len);
    defer std.crypto.secureZero(u8, plain);
    var ad_buf: [magic.len + Workspace.max_name_len]u8 = undefined;
    try Aead.decrypt(plain, cipher, tag.*, associatedData(workspace_name, &ad_buf), nonce.*, key.*);

    // `alloc_always`: the plaintext below is zeroed on return, so nothing may borrow from it.
    const parsed = try std.json.parseFromSliceLeaky(Json, aa, plain, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
    try vault.entries.ensureTotalCapacityPrecise(aa, parsed.entries.len);
    for (parsed.entries) |entry| vault.entries.appendAssumeCapacity(entry);
    return vault;
}

pub fn filePath(allocator: Allocator, ws: Workspace) ![]u8 {
    return std.fs.path.join(allocator, &.{ ws.dir, file_name });
}

/// `null` when the workspace has no vault yet.
pub fn load(allocator: Allocator, ws: Workspace) !?Vault {
    const path = try filePath(allocator, ws);
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(lp.io, path, allocator, .limited(max_file_len)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(bytes);

    var key: [Aead.key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    if (!try loadKey(allocator, ws, &key)) return error.VaultKeyMissing;
    return try decrypt(allocator, bytes, &key, ws.name);
}

/// Creates the key on the first save. Owner-only, written atomically.
pub fn save(self: *const Vault, allocator: Allocator, ws: Workspace) !void {
    var key: [Aead.key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    if (!try loadKey(allocator, ws, &key)) {
        try lp.io.randomSecure(&key);
        try storeKey(allocator, ws, &key);
    }
    const bytes = try self.encrypt(allocator, &key, ws.name);
    defer allocator.free(bytes);

    const path = try filePath(allocator, ws);
    defer allocator.free(path);
    var af = try std.Io.Dir.cwd().createFileAtomic(lp.io, path, .{ .replace = true, .permissions = Workspace.private_file });
    defer af.deinit(lp.io);
    try af.file.writeStreamingAll(lp.io, bytes);
    try af.replace(lp.io);
}

fn loadKey(allocator: Allocator, ws: Workspace, key: *[Aead.key_length]u8) !bool {
    if (builtin.os.tag == .macos) {
        return keychain.load(keychain_service, ws.name, key);
    }
    const path = try std.fs.path.join(allocator, &.{ ws.dir, key_file_name });
    defer allocator.free(path);
    const bytes = std.Io.Dir.cwd().readFileAlloc(lp.io, path, allocator, .limited(key.len)) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    if (bytes.len != key.len) return error.VaultKeyCorrupt;
    @memcpy(key, bytes);
    return true;
}

fn storeKey(allocator: Allocator, ws: Workspace, key: *const [Aead.key_length]u8) !void {
    if (builtin.os.tag == .macos) {
        return keychain.store(keychain_service, ws.name, key);
    }
    const path = try std.fs.path.join(allocator, &.{ ws.dir, key_file_name });
    defer allocator.free(path);
    log.warn(.app, "vault key kept in a file; no OS keychain on this platform", .{ .path = path });
    var af = try std.Io.Dir.cwd().createFileAtomic(lp.io, path, .{ .replace = true, .permissions = Workspace.private_file });
    defer af.deinit(lp.io);
    try af.file.writeStreamingAll(lp.io, key);
    try af.replace(lp.io);
}

// ---- Bitwarden unencrypted JSON export

pub const ImportCount = struct { imported: usize = 0, skipped: usize = 0 };

/// Login items (type 1) become entries: the name slugified, hosts from the
/// URIs, TOTP from a raw secret or an `otpauth://` URL. `folder` limits the
/// import to one Bitwarden folder, by name.
pub fn importBitwarden(self: *Vault, arena: Allocator, json_text: []const u8, folder: ?[]const u8) !ImportCount {
    const root = try std.json.parseFromSliceLeaky(std.json.Value, arena, json_text, .{});
    if (root != .object) return error.NotABitwardenExport;
    if (root.object.get("encrypted")) |enc| {
        if (enc == .bool and enc.bool) return error.EncryptedExport;
    }
    const folder_id: ?std.json.Value = if (folder) |want| blk: {
        const folders = root.object.get("folders") orelse return error.FolderNotFound;
        if (folders != .array) return error.FolderNotFound;
        for (folders.array.items) |f| {
            if (f != .object) continue;
            const name = f.object.get("name") orelse continue;
            if (name == .string and std.mem.eql(u8, name.string, want)) break :blk f.object.get("id") orelse .null;
        }
        return error.FolderNotFound;
    } else null;

    var count: ImportCount = .{};
    const items = root.object.get("items") orelse return error.NotABitwardenExport;
    if (items != .array) return error.NotABitwardenExport;
    for (items.array.items) |item| {
        if (item != .object) continue;
        const kind = item.object.get("type") orelse continue;
        if (kind != .integer or kind.integer != 1) continue;
        if (folder_id) |want| {
            const have = item.object.get("folderId") orelse .null;
            if (!jsonStringEql(have, want)) continue;
        }
        const login = item.object.get("login") orelse continue;
        if (login != .object) continue;
        const password = jsonString(login.object.get("password")) orelse {
            count.skipped += 1;
            continue;
        };
        const raw_name = jsonString(item.object.get("name")) orelse "";
        const name = try self.uniqueSlug(arena, raw_name);

        var hosts: std.ArrayList([]const u8) = .empty;
        if (login.object.get("uris")) |uris| {
            if (uris == .array) for (uris.array.items) |u| {
                if (u != .object) continue;
                const uri = jsonString(u.object.get("uri")) orelse continue;
                const host = hostOfUri(uri) orelse continue;
                try hosts.append(arena, host);
            };
        }
        const totp = if (jsonString(login.object.get("totp"))) |t| totpSecretOf(t) else null;
        try self.put(.{
            .name = name,
            .hosts = hosts.items,
            .username = jsonString(login.object.get("username")) orelse "",
            .password = password,
            .totp_secret = totp,
        });
        count.imported += 1;
    }
    return count;
}

fn jsonString(v: ?std.json.Value) ?[]const u8 {
    const val = v orelse return null;
    return if (val == .string) val.string else null;
}

fn jsonStringEql(a: std.json.Value, b: std.json.Value) bool {
    return a == .string and b == .string and std.mem.eql(u8, a.string, b.string);
}

/// `[a-z0-9_]` from any text, `item` when nothing survives, `_2`, `_3`… when
/// the vault already has the name.
fn uniqueSlug(self: *const Vault, arena: Allocator, raw: []const u8) error{OutOfMemory}![]const u8 {
    var slug: std.ArrayList(u8) = .empty;
    var pending_sep = false;
    for (raw) |c| {
        const lower = std.ascii.toLower(c);
        if (std.ascii.isAlphanumeric(lower) and lower < 0x80) {
            if (pending_sep and slug.items.len > 0) try slug.append(arena, '_');
            pending_sep = false;
            if (slug.items.len == max_name_len - 3) break;
            try slug.append(arena, lower);
        } else {
            pending_sep = true;
        }
    }
    const base = if (slug.items.len == 0) "item" else slug.items;
    if (self.find(base) == null) return base;
    var n: usize = 2;
    while (true) : (n += 1) {
        const candidate = try arena.print("{s}_{d}", .{ base, n });
        if (self.find(candidate) == null) return candidate;
    }
}

/// The host of a Bitwarden URI: `https://a.b/c` and bare `a.b` both give
/// `a.b`; non-web schemes give nothing.
pub fn hostOfUri(uri: []const u8) ?[]const u8 {
    var rest = uri;
    if (std.mem.find(u8, rest, "://")) |i| {
        const scheme = rest[0..i];
        if (!std.ascii.eqlIgnoreCase(scheme, "http") and !std.ascii.eqlIgnoreCase(scheme, "https")) return null;
        rest = rest[i + "://".len ..];
    }
    const end = std.mem.findAny(u8, rest, "/?#") orelse rest.len;
    var authority = rest[0..end];
    if (std.mem.findScalarLast(u8, authority, '@')) |at| authority = authority[at + 1 ..];
    if (std.mem.findScalarLast(u8, authority, ':')) |colon| {
        if (std.mem.findScalar(u8, authority, ']') == null) authority = authority[0..colon];
    }
    return if (authority.len == 0) null else authority;
}

/// Bitwarden stores either the bare base32 secret or an `otpauth://` URL.
fn totpSecretOf(totp: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, totp, "otpauth://")) return if (totp.len == 0) null else totp;
    const query_start = std.mem.findScalar(u8, totp, '?') orelse return null;
    var params = std.mem.splitScalar(u8, totp[query_start + 1 ..], '&');
    while (params.next()) |param| {
        if (std.mem.startsWith(u8, param, "secret=")) return param["secret=".len..];
    }
    return null;
}

fn lowerDupe(allocator: Allocator, text: []const u8) error{OutOfMemory}![]const u8 {
    const out = try allocator.alloc(u8, text.len);
    return std.ascii.lowerString(out, text);
}

// ---- The process's vault

/// One per process: `App.init` installs the workspace, the first placeholder
/// lookup opens the file, and the entries stay in memory until `uninstall`.
const Provider = union(enum) {
    none,
    locked: struct { allocator: Allocator, workspace: Workspace },
    open: Vault,
    /// No vault file, or one that would not open (logged once).
    absent,
};

var provider: Provider = .none;
var provider_mutex: std.Thread.Mutex = .{};

pub fn install(allocator: Allocator, workspace: Workspace) void {
    provider_mutex.lock();
    defer provider_mutex.unlock();
    provider = .{ .locked = .{ .allocator = allocator, .workspace = workspace } };
}

pub fn uninstall() void {
    provider_mutex.lock();
    defer provider_mutex.unlock();
    if (provider == .open) provider.open.deinit();
    provider = .none;
}

/// The workspace's vault, opened on first use; `null` when the process has
/// no workspace or the workspace has no vault.
pub fn current() ?*const Vault {
    provider_mutex.lock();
    defer provider_mutex.unlock();
    switch (provider) {
        .none, .absent => return null,
        .open => |*v| return v,
        .locked => |l| {
            const opened = load(l.allocator, l.workspace) catch |err| {
                log.err(.app, "vault would not open", .{ .workspace = l.workspace.name, .err = err });
                provider = .absent;
                return null;
            };
            provider = if (opened) |v| .{ .open = v } else .absent;
            return if (provider == .open) &provider.open else null;
        },
    }
}

// ---- Tests

const testing = std.testing;

fn testKey() [Aead.key_length]u8 {
    var key: [Aead.key_length]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i * 7 + 1);
    return key;
}

test "Vault: encrypt/decrypt round trip, wrong workspace and tampering fail" {
    var vault: Vault = .empty(testing.allocator);
    defer vault.deinit();
    try vault.put(.{ .name = "hn", .hosts = &.{"News.Ycombinator.com"}, .username = "alice", .password = "pw123", .totp_secret = "JBSWY3DPEHPK3PXP" });
    try vault.put(.{ .name = "gh", .hosts = &.{ "github.com", "api.github.com" }, .username = "bob", .password = "s3cret" });

    const key = testKey();
    const bytes = try vault.encrypt(testing.allocator, &key, "personal");
    defer testing.allocator.free(bytes);
    try testing.expect(std.mem.startsWith(u8, bytes, magic));
    try testing.expectEqual(null, std.mem.find(u8, bytes, "pw123"));
    try testing.expectEqual(null, std.mem.find(u8, bytes, "alice"));

    var back = try decrypt(testing.allocator, bytes, &key, "personal");
    defer back.deinit();
    try testing.expectEqual(2, back.entries.items.len);
    const hn = back.find("hn").?;
    try testing.expectEqualStrings("alice", hn.username);
    try testing.expectEqualStrings("pw123", hn.password);
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", hn.totp_secret.?);
    try testing.expectEqualStrings("news.ycombinator.com", hn.hosts[0]);
    try testing.expectEqual(null, back.find("gh").?.totp_secret);

    try testing.expectError(error.AuthenticationFailed, decrypt(testing.allocator, bytes, &key, "tedy"));

    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    tampered[magic.len + Aead.nonce_length + 3] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, decrypt(testing.allocator, tampered, &key, "personal"));

    var other = testKey();
    other[0] ^= 0xff;
    try testing.expectError(error.AuthenticationFailed, decrypt(testing.allocator, bytes, &other, "personal"));
    try testing.expectError(error.NotAVault, decrypt(testing.allocator, "LPV0", &key, "personal"));
}

test "Vault: put replaces by name, remove" {
    var vault: Vault = .empty(testing.allocator);
    defer vault.deinit();
    try vault.put(.{ .name = "a", .hosts = &.{"a.com"}, .username = "u1", .password = "p1" });
    try vault.put(.{ .name = "a", .hosts = &.{"b.com"}, .username = "u2", .password = "p2" });
    try testing.expectEqual(1, vault.entries.items.len);
    try testing.expectEqualStrings("u2", vault.find("a").?.username);
    try testing.expectError(error.InvalidName, vault.put(.{ .name = "Bad-Name", .hosts = &.{}, .username = "", .password = "" }));
    try testing.expectEqual(true, vault.remove("a"));
    try testing.expectEqual(false, vault.remove("a"));
    try testing.expectEqual(0, vault.entries.items.len);
}

test "Vault: placeholder parse" {
    var buf: [max_name_len]u8 = undefined;
    const hn = parsePlaceholder("LP_HN_PASSWORD", &buf).?;
    try testing.expectEqualStrings("hn", hn.entry);
    try testing.expectEqual(Field.password, hn.field);

    const nested = parsePlaceholder("LP_MY_SITE_2_TOTP", &buf).?;
    try testing.expectEqualStrings("my_site_2", nested.entry);
    try testing.expectEqual(Field.totp, nested.field);
    try testing.expectEqual(Field.username, parsePlaceholder("LP_X_USERNAME", &buf).?.field);

    try testing.expectEqual(null, parsePlaceholder("LP_PASSWORD", &buf));
    try testing.expectEqual(null, parsePlaceholder("LP_HN_TOKEN", &buf));
    try testing.expectEqual(null, parsePlaceholder("HN_PASSWORD", &buf));
    try testing.expectEqual(null, parsePlaceholder("LP__PASSWORD", &buf));
    try testing.expectEqual(null, parsePlaceholder("LP_hn_PASSWORD", &buf));
    const long: [max_name_len + 1]u8 = @splat('A');
    const too_long = try std.mem.concat(testing.allocator, u8, &.{ "LP_", &long, "_PASSWORD" });
    defer testing.allocator.free(too_long);
    try testing.expectEqual(null, parsePlaceholder(too_long, &buf));

    const name = try placeholderName(testing.allocator, "my_site", .totp);
    defer testing.allocator.free(name);
    try testing.expectEqualStrings("LP_MY_SITE_TOTP", name);
}

test "Vault: host match" {
    const cases = [_]struct { pattern: []const u8, host: []const u8, ok: bool }{
        .{ .pattern = "ycombinator.com", .host = "ycombinator.com", .ok = true },
        .{ .pattern = "ycombinator.com", .host = "news.ycombinator.com", .ok = true },
        .{ .pattern = "ycombinator.com", .host = "a.b.ycombinator.com", .ok = true },
        .{ .pattern = "ycombinator.com", .host = "News.YCombinator.COM", .ok = true },
        .{ .pattern = "127.0.0.1", .host = "127.0.0.1", .ok = true },
        .{ .pattern = "ycombinator.com", .host = "evil-ycombinator.com", .ok = false },
        .{ .pattern = "ycombinator.com", .host = "ycombinator.com.evil.com", .ok = false },
        .{ .pattern = "ycombinator.com", .host = "ycombinator.co", .ok = false },
        .{ .pattern = "ycombinator.com", .host = "", .ok = false },
        .{ .pattern = "127.0.0.1", .host = "localhost", .ok = false },
        .{ .pattern = "news.ycombinator.com", .host = "ycombinator.com", .ok = false },
    };
    for (cases) |c| {
        try testing.expectEqual(c.ok, hostMatches(c.pattern, c.host));
    }
}

test "Vault: lookup binds to host, unbound does not" {
    var vault: Vault = .empty(testing.allocator);
    defer vault.deinit();
    try vault.put(.{ .name = "hn", .hosts = &.{"ycombinator.com"}, .username = "alice", .password = "pw123" });

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    try testing.expectEqualStrings("pw123", (try vault.lookup(aa, "LP_HN_PASSWORD", "news.ycombinator.com")).value);
    try testing.expectEqualStrings("alice", (try vault.lookup(aa, "LP_HN_USERNAME", "ycombinator.com")).value);
    try testing.expectEqual(Lookup.none, try vault.lookup(aa, "LP_HN_TOTP", "ycombinator.com"));
    try testing.expectEqual(Lookup.none, try vault.lookup(aa, "LP_OTHER_PASSWORD", "ycombinator.com"));
    try testing.expectEqual(Lookup.none, try vault.lookup(aa, "LP_PASSWORD", "ycombinator.com"));

    const mismatch = try vault.lookup(aa, "LP_HN_PASSWORD", "evil.com");
    try testing.expectEqualStrings("hn", mismatch.host_mismatch.name);
    try testing.expectEqual(std.meta.Tag(Lookup).host_mismatch, std.meta.activeTag(try vault.lookup(aa, "LP_HN_PASSWORD", null)));

    try testing.expectEqualStrings("pw123", (try vault.unbound(aa, "LP_HN_PASSWORD")).?);
    try testing.expectEqual(null, try vault.unbound(aa, "LP_HN_TOTP"));
    try testing.expectEqualStrings("hn", vault.forHost("news.ycombinator.com").?.name);
    try testing.expectEqual(null, vault.forHost("evil.com"));

    const listed = try vault.names(aa);
    try testing.expectEqual(2, listed.len);
    try testing.expectEqualStrings("LP_HN_USERNAME", listed[0]);
    try testing.expectEqualStrings("LP_HN_PASSWORD", listed[1]);
}

test "Vault: TOTP against RFC 6238 SHA-1 vectors" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    // "12345678901234567890" in base32.
    const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    const cases = [_]struct { t: u64, code: []const u8 }{
        .{ .t = 59, .code = "287082" },
        .{ .t = 1111111109, .code = "081804" },
        .{ .t = 1111111111, .code = "050471" },
        .{ .t = 1234567890, .code = "005924" },
        .{ .t = 2000000000, .code = "279037" },
        .{ .t = 20000000000, .code = "353130" },
    };
    var code: [6]u8 = undefined;
    for (cases) |c| {
        try totpCode(aa, secret, c.t, &code);
        try testing.expectEqualStrings(c.code, &code);
    }
    try testing.expectEqualStrings("12345678901234567890", try base32Decode(aa, "gezd gnbv-GY3TQOJQGEZDGNBVGY3TQOJQ===="));
    try testing.expectError(error.InvalidBase32, base32Decode(aa, "not base32!"));
    try testing.expectError(error.InvalidBase32, base32Decode(aa, ""));
}

test "Vault: Bitwarden import" {
    const fixture =
        \\{"encrypted": false,
        \\ "folders": [{"id": "f-1", "name": "Work"}, {"id": "f-2", "name": "Home"}],
        \\ "items": [
        \\  {"type": 1, "name": "Hacker News", "folderId": "f-1",
        \\   "login": {"uris": [{"match": null, "uri": "https://news.ycombinator.com/login"}, {"uri": "ycombinator.com:443/x"}, {"uri": "androidapp://com.example"}],
        \\             "username": "alice", "password": "pw123", "totp": "otpauth://totp/HN:alice?secret=JBSWY3DPEHPK3PXP&issuer=HN"}},
        \\  {"type": 1, "name": "Hacker News", "folderId": "f-1",
        \\   "login": {"uris": [{"uri": "https://user:pw@old.ycombinator.com:8080/"}], "username": "bob", "password": "pw456", "totp": "JBSWY3DPEHPK3PXP"}},
        \\  {"type": 1, "name": "No password", "folderId": "f-1", "login": {"username": "x", "password": null}},
        \\  {"type": 2, "name": "A note", "folderId": "f-1", "secureNote": {}},
        \\  {"type": 1, "name": "Bank", "folderId": "f-2", "login": {"uris": [{"uri": "https://bank.example"}], "username": "c", "password": "d"}}
        \\ ]}
    ;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    var vault: Vault = .empty(testing.allocator);
    defer vault.deinit();
    const work = try vault.importBitwarden(arena.allocator(), fixture, "Work");
    try testing.expectEqual(2, work.imported);
    try testing.expectEqual(1, work.skipped);
    try testing.expectEqual(2, vault.entries.items.len);

    const hn = vault.find("hacker_news").?;
    try testing.expectEqual(2, hn.hosts.len);
    try testing.expectEqualStrings("news.ycombinator.com", hn.hosts[0]);
    try testing.expectEqualStrings("ycombinator.com", hn.hosts[1]);
    try testing.expectEqualStrings("alice", hn.username);
    try testing.expectEqualStrings("pw123", hn.password);
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", hn.totp_secret.?);

    const hn2 = vault.find("hacker_news_2").?;
    try testing.expectEqualStrings("old.ycombinator.com", hn2.hosts[0]);
    try testing.expectEqualStrings("JBSWY3DPEHPK3PXP", hn2.totp_secret.?);

    const all = try vault.importBitwarden(arena.allocator(), fixture, null);
    try testing.expectEqual(3, all.imported);
    try testing.expect(vault.find("bank") != null);
    try testing.expectError(error.FolderNotFound, vault.importBitwarden(arena.allocator(), fixture, "Nope"));
    try testing.expectError(error.EncryptedExport, vault.importBitwarden(arena.allocator(), "{\"encrypted\": true, \"items\": []}", null));
}

test "Vault: save and load through a workspace" {
    if (builtin.os.tag == .macos) return error.SkipZigTest; // would touch the login Keychain
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(lp.io, ".", testing.allocator);
    defer testing.allocator.free(root);
    const ws = try Workspace.open(testing.allocator, root, "e2e");
    defer ws.deinit(testing.allocator);

    try testing.expectEqual(null, try load(testing.allocator, ws));
    var vault: Vault = .empty(testing.allocator);
    defer vault.deinit();
    try vault.put(.{ .name = "site", .hosts = &.{"127.0.0.1"}, .username = "alice", .password = "pw123" });
    try vault.save(testing.allocator, ws);

    var back = (try load(testing.allocator, ws)).?;
    defer back.deinit();
    try testing.expectEqualStrings("pw123", back.find("site").?.password);
}
