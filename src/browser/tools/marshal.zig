// Copyright (C) 2023-2026  Lightpanda (Selecy SAS)
//
// Francis Bouvier <francis@lightpanda.io>
// Pierre Tachoire <pierre@lightpanda.io>
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

//! A tool call's arguments, from the JSON a caller sent to the struct the
//! tool reads: the schema's own casing, the `$LP_*` placeholders that keep a
//! credential out of a model's context, and what a malformed call is told.

const std = @import("std");
const lp = @import("../../lightpanda.zig");

const NodeRegistry = @import("../../NodeRegistry.zig");
const Vault = @import("../../Vault.zig");
const tools = @import("../tools.zig");
const Tool = tools.Tool;
const testing = @import("../../testing.zig");
const log = lp.log;

const ParseArgsError = error{ OutOfMemory, InvalidParams };

/// Names the first required argument absent from the call, so a bare
/// `InvalidParams` from `parseValue` doesn't hide which field to add — a
/// caller sending `{"expression": ...}` to evaluate learns about `script`.
/// Default-true booleans (setChecked.checked) parse fine when omitted, so
/// they don't count as missing. Runs on normalized arguments.
pub fn diagnoseMissingRequired(arena: std.mem.Allocator, tool: Tool, arguments: ?std.json.Value) ?[]const u8 {
    const schemas = lp.Schema.all();
    const tool_idx = @backingInt(tool);
    if (tool_idx >= schemas.len) return null;
    const schema = schemas[tool_idx];

    const obj = if (arguments) |v| switch (v) {
        .object => |o| o,
        // A non-object shape fails in parseValue with the whole payload as
        // context; there is no key to name here.
        else => return null,
    } else std.json.ObjectMap.empty;
    for (schema.required) |name| {
        if (obj.get(name) != null) continue;
        if (schema.findField(name)) |f| {
            if (f.default_true) continue;
        }
        return arena.print("missing required argument '{s}'", .{name}) catch null;
    }
    return null;
}

/// Surface field/value context for known typed args — `std.json`'s parse
/// errors only carry the tag (`InvalidEnumTag`, …), not which field failed.
pub fn diagnoseArgs(arena: std.mem.Allocator, arguments: ?std.json.Value) ?[]const u8 {
    const args = arguments orelse return null;
    if (args != .object) return null;

    if (args.object.get("state")) |v| switch (v) {
        .string => |s| if (std.meta.stringToEnum(lp.Config.WaitUntil, s) == null)
            return formatEnumError(arena, "state", s, lp.Config.WaitUntil),
        else => return arena.print("state must be a string", .{}) catch null,
    };

    return null;
}

fn formatEnumError(arena: std.mem.Allocator, field: []const u8, got: []const u8, comptime E: type) ?[]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    aw.writer.print("invalid {s} '{s}'. Expected one of: ", .{ field, got }) catch return null;
    inline for (@typeInfo(E).@"enum".field_names, 0..) |field_name, i| {
        if (i > 0) aw.writer.writeAll(", ") catch return null;
        aw.writer.writeAll(field_name) catch return null;
    }
    return aw.written();
}

pub fn parseValue(comptime T: type, arena: std.mem.Allocator, value: std.json.Value) ParseArgsError!T {
    var parsed = std.json.parseFromValueLeaky(T, arena, value, .{ .ignore_unknown_fields = true }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            log.debug(.browser, "parseValue rejected", .{ .err = @errorName(err), .type = @typeName(T) });
            return error.InvalidParams;
        },
    };
    // Schema contract: backendNodeId 0 and url "" mean omitted. Registry ids
    // start at 1 and "" is no URL; zero-filling models (gpt-5.x) send them for
    // "unset", and navigating to "" would tear the page down.
    if (comptime @typeInfo(T) == .@"struct" and @hasField(T, "backendNodeId") and
        @typeInfo(@FieldType(T, "backendNodeId")) == .optional)
    {
        if (parsed.backendNodeId) |nid| {
            if (nid == 0) parsed.backendNodeId = null;
        }
    }
    if (comptime @typeInfo(T) == .@"struct" and @hasField(T, "url") and
        @typeInfo(@FieldType(T, "url")) == .optional)
    {
        if (parsed.url) |u| {
            if (u.len == 0) parsed.url = null;
        }
    }
    return parsed;
}

/// For tools where every field is optional. Missing args → default `T`;
/// wrong-typed args still error (don't silently default).
pub fn parseArgsOrDefault(comptime T: type, arena: std.mem.Allocator, arguments: ?std.json.Value) ParseArgsError!T {
    return parseValue(T, arena, arguments orelse return .{});
}

/// Required-args parse: missing or malformed both surface as `InvalidParams`.
pub fn parseArgs(comptime T: type, arena: std.mem.Allocator, arguments: ?std.json.Value) ParseArgsError!T {
    return parseValue(T, arena, arguments orelse return error.InvalidParams);
}

/// Renames keys to the schema's casing and drops `null` values, which
/// zero-filling models send for "unset" but `std.json` rejects for a
/// non-optional field.
pub fn normalizeArgs(arena: std.mem.Allocator, tool: Tool, args: ?std.json.Value) !?std.json.Value {
    const v = args orelse return null;
    if (v != .object) return v;

    const schemas = lp.Schema.all();
    const tool_idx = @backingInt(tool);
    if (tool_idx >= schemas.len) return v;
    const schema = schemas[tool_idx];

    var it = v.object.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == .null) break;
        const field = schema.findField(entry.key_ptr.*) orelse continue;
        if (!std.mem.eql(u8, field.name, entry.key_ptr.*)) break;
    } else return v;

    var new_obj: std.json.ObjectMap = .empty;
    try new_obj.ensureTotalCapacity(arena, v.object.count());
    it = v.object.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* == .null) continue;
        const canonical = if (schema.findField(entry.key_ptr.*)) |f| f.name else entry.key_ptr.*;
        const gop = try new_obj.getOrPut(arena, canonical);
        if (gop.found_existing) return error.DuplicateField;
        gop.value_ptr.* = entry.value_ptr.*;
    }
    return .{ .object = new_obj };
}

/// The `LP_*` names the model may list: the live environment (walked each
/// time: `setenv` can free both the environ array and its entry strings) and
/// the workspace vault's placeholders, sorted and deduplicated.
pub fn lpEnvNames(arena: std.mem.Allocator) error{OutOfMemory}![]const []const u8 {
    var env_names: std.ArrayList([]const u8) = .empty;
    var ptr = std.c.environ;
    while (ptr[0]) |entry| : (ptr += 1) {
        const line = std.mem.span(entry);
        const eq_idx = std.mem.findScalar(u8, line, '=') orelse continue;
        const name = line[0..eq_idx];
        if (!std.mem.startsWith(u8, name, "LP_")) continue;
        try env_names.append(arena, try arena.dupe(u8, name));
    }
    if (Vault.current()) |vault| {
        try env_names.appendSlice(arena, try vault.names(arena));
    }
    std.mem.sort([]const u8, env_names.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lt);
    var unique: usize = 0;
    for (env_names.items, 0..) |name, i| {
        if (i > 0 and std.mem.eql(u8, name, env_names.items[unique - 1])) continue;
        env_names.items[unique] = name;
        unique += 1;
    }
    env_names.items.len = unique;
    return env_names.toOwnedSlice(arena);
}

/// Resolve an LP_-prefixed environment variable, or `null` for any other name.
/// Only the LP_ namespace is readable from the model; everything else
/// (provider API keys, system env, third-party secrets) is hidden so the LLM
/// can't probe for it. Same pattern as Kakoune's `kak_*`.
pub fn lookupLpEnv(name: []const u8) ?[:0]const u8 {
    if (!std.mem.startsWith(u8, name, "LP_")) return null;
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) {
        log.debug(.browser, "getEnv name too long", .{ .name_len = name.len, .limit = name_buf.len - 1 });
        return null;
    }
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;
    const value = std.c.getenv(name_buf[0..name.len :0]) orelse return null;
    return std.mem.span(value);
}

/// Whether `getEnv` may show the model this name's value. A vault entry's
/// placeholders never, and by the same rule any `*_PASSWORD` / `*_TOTP`
/// from the environment: those are for `$NAME` in a tool argument only.
pub fn modelReadable(name: []const u8) bool {
    if (std.mem.endsWith(u8, name, "_PASSWORD") or std.mem.endsWith(u8, name, "_TOTP")) return false;
    var buf: [Vault.max_name_len]u8 = undefined;
    const ph = Vault.parsePlaceholder(name, &buf) orelse return true;
    const vault = Vault.current() orelse return true;
    return vault.find(ph.entry) == null;
}

/// The vault entry bound to `host`, for bare `/login` to pick.
pub fn vaultEntryForHost(host: ?[]const u8) ?[]const u8 {
    const vault = Vault.current() orelse return null;
    const entry = vault.forHost(host orelse return null) orelse return null;
    return entry.name;
}

const Resolved = union(enum) {
    none,
    value: []const u8,
    refused: *const Vault.Entry,
};

/// The vault answers first, bound to `host`; the environment has no binding.
fn resolve(arena: std.mem.Allocator, name: []const u8, host: ?[]const u8) error{OutOfMemory}!Resolved {
    if (Vault.current()) |vault| {
        switch (try vault.lookup(arena, name, host)) {
            .none => {},
            .value => |v| return .{ .value = v },
            .host_mismatch => |entry| return .{ .refused = entry },
        }
    }
    if (lookupLpEnv(name)) |v| return .{ .value = v };
    return .none;
}

pub const SubstituteError = error{ OutOfMemory, CredentialHostMismatch };

/// Resolve `$LP_*` placeholders in every string arg before the tool runs.
/// `fill.value` is the one exception: `execFill` resolves it internally and
/// echoes the original placeholder so the credential never surfaces in the
/// result text. `host` is the current page's, which a vault value must be
/// bound to; on `error.CredentialHostMismatch`, `hostMismatchText` says why.
pub fn substituteStringArgs(arena: std.mem.Allocator, tool: Tool, args: ?std.json.Value, host: ?[]const u8) SubstituteError!?std.json.Value {
    const v = args orelse return null;
    if (v != .object) return v;

    const is_fill = tool == .fill;

    const needsSub = struct {
        fn f(is_fill_: bool, key: []const u8, val: std.json.Value) bool {
            if (is_fill_ and std.mem.eql(u8, key, "value")) return false;
            return val == .string and std.mem.find(u8, val.string, "$LP_") != null;
        }
    }.f;

    var it = v.object.iterator();
    while (it.next()) |entry| {
        if (needsSub(is_fill, entry.key_ptr.*, entry.value_ptr.*)) break;
    } else return v;

    var new_obj: std.json.ObjectMap = .empty;
    try new_obj.ensureTotalCapacity(arena, v.object.count());
    it = v.object.iterator();
    while (it.next()) |entry| {
        const key = entry.key_ptr.*;
        const val = entry.value_ptr.*;
        const new_val: std.json.Value = if (needsSub(is_fill, key, val))
            .{ .string = try substituteEnvVars(arena, val.string, host) }
        else
            val;
        try new_obj.put(arena, key, new_val);
    }
    return .{ .object = new_obj };
}

/// `$NAME` runs: `$` then `[A-Za-z0-9_]+`, from the first `$LP_` on. Pages
/// routinely contain `$5.99`-style content where `$` is incidental.
const PlaceholderIterator = struct {
    input: []const u8,
    i: usize,

    const Match = struct { start: usize, end: usize, name: []const u8 };

    fn init(input: []const u8) ?PlaceholderIterator {
        const first_lp = std.mem.find(u8, input, "$LP_") orelse return null;
        return .{ .input = input, .i = first_lp };
    }

    fn next(self: *PlaceholderIterator) ?Match {
        while (std.mem.findScalarPos(u8, self.input, self.i, '$')) |dollar| {
            const var_start = dollar + 1;
            var var_end = var_start;
            while (var_end < self.input.len and (std.ascii.isAlphanumeric(self.input[var_end]) or self.input[var_end] == '_')) {
                var_end += 1;
            }
            if (var_end == var_start) {
                self.i = dollar + 1;
                continue;
            }
            self.i = var_end;
            return .{ .start = dollar, .end = var_end, .name = self.input[var_start..var_end] };
        }
        return null;
    }
};

pub fn substituteEnvVars(arena: std.mem.Allocator, input: []const u8, host: ?[]const u8) SubstituteError![]const u8 {
    // Lowercase `$lp_…` falls through here too — `getenv` is
    // case-sensitive on Linux, so it would never resolve anyway.
    var it = PlaceholderIterator.init(input) orelse return input;

    var result: std.ArrayList(u8) = .empty;
    try result.ensureTotalCapacity(arena, input.len);
    var last_copy: usize = 0;
    while (it.next()) |m| {
        switch (try resolve(arena, m.name, host)) {
            .none => {},
            .value => |val| {
                try result.appendSlice(arena, input[last_copy..m.start]);
                try result.appendSlice(arena, val);
                last_copy = m.end;
            },
            .refused => |entry| {
                log.warn(.browser, "credential host mismatch", .{ .placeholder = m.name, .entry = entry.name, .host = host orelse "(no page)" });
                return error.CredentialHostMismatch;
            },
        }
    }
    if (last_copy == 0) return input;
    try result.appendSlice(arena, input[last_copy..]);
    return result.toOwnedSlice(arena);
}

/// Why `substituteEnvVars` refused `input` for `host`: the placeholder, its
/// entry and the entry's hosts, never the value. `args` may be a string or
/// the tool's argument object.
pub fn hostMismatchText(arena: std.mem.Allocator, args: ?std.json.Value, host: ?[]const u8) error{OutOfMemory}![]const u8 {
    const v = args orelse return generic_mismatch;
    switch (v) {
        .string => |s| return hostMismatchTextFor(arena, s, host),
        .object => |o| {
            var it = o.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.* != .string) continue;
                const text = try hostMismatchTextFor(arena, entry.value_ptr.string, host);
                if (text.ptr != generic_mismatch.ptr) return text;
            }
            return generic_mismatch;
        },
        else => return generic_mismatch,
    }
}

const generic_mismatch = "a vault credential in the arguments is bound to another host; it stays in the vault";

fn hostMismatchTextFor(arena: std.mem.Allocator, input: []const u8, host: ?[]const u8) error{OutOfMemory}![]const u8 {
    var it = PlaceholderIterator.init(input) orelse return generic_mismatch;
    while (it.next()) |m| {
        switch (try resolve(arena, m.name, host)) {
            .refused => |entry| {
                const hosts = try std.mem.join(arena, ", ", entry.hosts);
                return if (host) |h|
                    try arena.print("${s} belongs to vault entry \"{s}\", bound to {s}; the current page is on {s}, so it stays in the vault", .{ m.name, entry.name, hosts, h })
                else
                    try arena.print("${s} belongs to vault entry \"{s}\", bound to {s}; no page is loaded, so it stays in the vault", .{ m.name, entry.name, hosts });
            },
            else => {},
        }
    }
    return generic_mismatch;
}

/// Inverse of `substituteEnvVars`, used by the recorder so a credential the
/// agent retyped as a literal doesn't leak into the recording. Vault values
/// count whatever page produced them. Values < 4 chars are skipped to avoid
/// false-positive substring matches.
pub fn reverseSubstituteEnvVars(arena: std.mem.Allocator, input: []const u8) error{OutOfMemory}![]const u8 {
    if (input.len < 4) return input;
    const env_names = try lpEnvNames(arena);
    const vault = Vault.current();

    // Iterate by value length descending. With two LP_* values where one is a
    // substring of the other (both ≥4 chars so neither is filtered), name-order
    // iteration would let the shorter value clobber part of the longer one
    // before its full match is found, leaking a suffix into the recording.
    const Pair = struct { name: []const u8, value: []const u8 };
    var pairs: std.ArrayList(Pair) = .empty;
    try pairs.ensureTotalCapacityPrecise(arena, env_names.len);
    for (env_names) |name| {
        const value = (if (vault) |v| try v.unbound(arena, name) else null) orelse lookupLpEnv(name) orelse continue;
        if (value.len < 4) continue;
        pairs.appendAssumeCapacity(.{ .name = name, .value = value });
    }
    std.mem.sort(Pair, pairs.items, {}, struct {
        fn lt(_: void, a: Pair, b: Pair) bool {
            return a.value.len > b.value.len;
        }
    }.lt);

    var current: []const u8 = input;
    var changed = false;
    for (pairs.items) |p| {
        if (std.mem.find(u8, current, p.value) == null) continue;
        const placeholder = try arena.print("${s}", .{p.name});
        current = try std.mem.replaceOwned(u8, arena, current, p.value, placeholder);
        changed = true;
    }
    return if (changed) current else input;
}

test "parseValue: zero-filled optional backendNodeId treated as omitted" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const Params = struct {
        backendNodeId: ?NodeRegistry.Id = null,
        maxDepth: ?u32 = null,
    };
    const zeroed = try std.json.parseFromSliceLeaky(std.json.Value, aa,
        \\{"backendNodeId":0,"maxDepth":2}
    , .{});
    const args = try parseValue(Params, aa, zeroed);
    try std.testing.expectEqual(@as(?NodeRegistry.Id, null), args.backendNodeId);
    try std.testing.expectEqual(@as(?u32, 2), args.maxDepth);

    const real = try std.json.parseFromSliceLeaky(std.json.Value, aa,
        \\{"backendNodeId":7}
    , .{});
    try std.testing.expectEqual(@as(?NodeRegistry.Id, 7), (try parseValue(Params, aa, real)).backendNodeId);

    // Non-optional ids (nodeDetails) pass through untouched.
    const Required = struct { backendNodeId: NodeRegistry.Id };
    const zero_required = try std.json.parseFromSliceLeaky(std.json.Value, aa,
        \\{"backendNodeId":0}
    , .{});
    try std.testing.expectEqual(@as(NodeRegistry.Id, 0), (try parseValue(Required, aa, zero_required)).backendNodeId);
}

test "parseValue: empty optional url treated as omitted" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const Params = struct { url: ?[:0]const u8 = null };
    const empty = try std.json.parseFromSliceLeaky(std.json.Value, aa,
        \\{"url":""}
    , .{});
    try std.testing.expect((try parseValue(Params, aa, empty)).url == null);

    const real = try std.json.parseFromSliceLeaky(std.json.Value, aa,
        \\{"url":"https://example.com"}
    , .{});
    try std.testing.expectEqualStrings("https://example.com", (try parseValue(Params, aa, real)).url.?);
}

test "normalizeArgs: a null field takes its default" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    const Params = struct { selector: []const u8, checked: bool = true };
    const args = try std.json.parseFromSliceLeaky(std.json.Value, aa,
        \\{"Selector":"#x","checked":null}
    , .{});
    const parsed = try parseValue(Params, aa, (try normalizeArgs(aa, .setChecked, args)).?);
    try std.testing.expectEqualStrings("#x", parsed.selector);
    try std.testing.expect(parsed.checked);
}

test "substituteEnvVars resolves LP_* vars" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const var_name = "LP_SUBST_TEST";
    const var_value = "secret";
    _ = testing.setenv(@constCast(var_name), @constCast(var_value), 1);
    defer _ = testing.unsetenv(@constCast(var_name));

    const r = try substituteEnvVars(arena.allocator(), "user=$LP_SUBST_TEST/end", null);
    try std.testing.expectEqualStrings("user=secret/end", r);
}

test "substituteEnvVars keeps non-LP_ refs literal even when set" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // `execGetEnv` hides non-LP_ vars from the model; `substituteEnvVars`
    // must hide them too, otherwise a prompt-injected `fill('$X')` would
    // resolve the value into the page DOM.
    const var_name = "LIGHTPANDA_SUBST_TEST_OUTSIDE";
    const var_value = "should-not-leak";
    _ = testing.setenv(@constCast(var_name), @constCast(var_value), 1);
    defer _ = testing.unsetenv(@constCast(var_name));

    const r = try substituteEnvVars(arena.allocator(), "$LIGHTPANDA_SUBST_TEST_OUTSIDE", null);
    try std.testing.expectEqualStrings("$LIGHTPANDA_SUBST_TEST_OUTSIDE", r);
}

test "substituteEnvVars missing LP_ var kept literal" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const r = try substituteEnvVars(arena.allocator(), "$LP_UNLIKELY_VAR_12345", null);
    try std.testing.expectEqualStrings("$LP_UNLIKELY_VAR_12345", r);
}

test "substituteEnvVars bare dollar" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const r = try substituteEnvVars(arena.allocator(), "price is $ 5", null);
    try std.testing.expectEqualStrings("price is $ 5", r);
}

test "substituteEnvVars: vault values are bound to the page host" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const aa = arena.allocator();

    var vault: Vault = .empty(std.testing.allocator);
    try vault.put(.{ .name = "site", .hosts = &.{"127.0.0.1"}, .username = "alice", .password = "pw123" });
    Vault.installOpen(vault);
    defer Vault.uninstall();

    try std.testing.expectEqualStrings("u=alice p=pw123", try substituteEnvVars(aa, "u=$LP_SITE_USERNAME p=$LP_SITE_PASSWORD", "127.0.0.1"));
    try std.testing.expectError(error.CredentialHostMismatch, substituteEnvVars(aa, "p=$LP_SITE_PASSWORD", "localhost"));
    try std.testing.expectError(error.CredentialHostMismatch, substituteEnvVars(aa, "p=$LP_SITE_PASSWORD", null));
    // An unknown placeholder is left alone, whatever the host.
    try std.testing.expectEqualStrings("$LP_OTHER_PASSWORD", try substituteEnvVars(aa, "$LP_OTHER_PASSWORD", "localhost"));

    const text = try hostMismatchText(aa, .{ .string = "p=$LP_SITE_PASSWORD" }, "localhost");
    try std.testing.expectEqualStrings("$LP_SITE_PASSWORD belongs to vault entry \"site\", bound to 127.0.0.1; the current page is on localhost, so it stays in the vault", text);
    try std.testing.expectEqual(null, std.mem.find(u8, text, "pw123"));

    var args: std.json.ObjectMap = .empty;
    try args.put(aa, "selector", .{ .string = "#pw" });
    try args.put(aa, "text", .{ .string = "$LP_SITE_PASSWORD" });
    try std.testing.expectError(error.CredentialHostMismatch, substituteStringArgs(aa, .evaluate, .{ .object = args }, "localhost"));
    try std.testing.expect(std.mem.startsWith(u8, try hostMismatchText(aa, .{ .object = args }, null), "$LP_SITE_PASSWORD belongs to vault entry \"site\", bound to 127.0.0.1; no page is loaded"));

    // `fill.value` is left for `execFill`, so no host check here.
    var fill_args: std.json.ObjectMap = .empty;
    try fill_args.put(aa, "value", .{ .string = "$LP_SITE_PASSWORD" });
    const kept = (try substituteStringArgs(aa, .fill, .{ .object = fill_args }, "localhost")).?;
    try std.testing.expectEqualStrings("$LP_SITE_PASSWORD", kept.object.get("value").?.string);

    try std.testing.expectEqual(false, modelReadable("LP_SITE_USERNAME"));
    try std.testing.expectEqual(false, modelReadable("LP_SITE_PASSWORD"));
    try std.testing.expectEqual(false, modelReadable("LP_PASSWORD"));
    try std.testing.expectEqual(false, modelReadable("LP_HN_TOTP"));
    try std.testing.expectEqual(true, modelReadable("LP_OTHER_USERNAME"));
    try std.testing.expectEqual(true, modelReadable("LP_EMAIL"));

    try std.testing.expectEqualStrings("site", vaultEntryForHost("127.0.0.1").?);
    try std.testing.expectEqual(null, vaultEntryForHost("localhost"));
    try std.testing.expectEqual(null, vaultEntryForHost(null));

    const names = try lpEnvNames(aa);
    var seen: usize = 0;
    for (names) |n| {
        if (std.mem.eql(u8, n, "LP_SITE_USERNAME") or std.mem.eql(u8, n, "LP_SITE_PASSWORD")) seen += 1;
    }
    try std.testing.expectEqual(2, seen);

    // Recordings scrub vault values whatever page produced them.
    try std.testing.expectEqualStrings("fill('#pw', '$LP_SITE_PASSWORD')", try reverseSubstituteEnvVars(aa, "fill('#pw', 'pw123')"));
}
