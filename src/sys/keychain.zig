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

//! Generic-password items in the macOS login Keychain, through
//! Security.framework. Only what the vault key needs: one blob per
//! (service, account).

const std = @import("std");

const CFTypeRef = ?*const anyopaque;
const CFIndex = isize;
const OSStatus = i32;

const kCFStringEncodingUTF8: u32 = 0x0800_0100;
const errSecItemNotFound: OSStatus = -25300;

const CFDictionaryKeyCallBacks = extern struct {
    version: CFIndex,
    retain: ?*const anyopaque,
    release: ?*const anyopaque,
    copyDescription: ?*const anyopaque,
    equal: ?*const anyopaque,
    hash: ?*const anyopaque,
};
const CFDictionaryValueCallBacks = extern struct {
    version: CFIndex,
    retain: ?*const anyopaque,
    release: ?*const anyopaque,
    copyDescription: ?*const anyopaque,
    equal: ?*const anyopaque,
};

extern const kCFTypeDictionaryKeyCallBacks: CFDictionaryKeyCallBacks;
extern const kCFTypeDictionaryValueCallBacks: CFDictionaryValueCallBacks;
extern const kCFBooleanTrue: CFTypeRef;
extern const kSecClass: CFTypeRef;
extern const kSecClassGenericPassword: CFTypeRef;
extern const kSecAttrService: CFTypeRef;
extern const kSecAttrAccount: CFTypeRef;
extern const kSecValueData: CFTypeRef;
extern const kSecReturnData: CFTypeRef;
extern const kSecMatchLimit: CFTypeRef;
extern const kSecMatchLimitOne: CFTypeRef;

extern fn CFStringCreateWithBytes(alloc: CFTypeRef, bytes: [*]const u8, len: CFIndex, encoding: u32, is_external: bool) CFTypeRef;
extern fn CFDataCreate(alloc: CFTypeRef, bytes: [*]const u8, len: CFIndex) CFTypeRef;
extern fn CFDataGetLength(data: CFTypeRef) CFIndex;
extern fn CFDataGetBytePtr(data: CFTypeRef) [*]const u8;
extern fn CFDictionaryCreate(alloc: CFTypeRef, keys: [*]const CFTypeRef, values: [*]const CFTypeRef, count: CFIndex, key_cb: *const CFDictionaryKeyCallBacks, value_cb: *const CFDictionaryValueCallBacks) CFTypeRef;
extern fn CFRelease(ref: CFTypeRef) void;
extern fn SecItemAdd(attrs: CFTypeRef, result: ?*CFTypeRef) OSStatus;
extern fn SecItemCopyMatching(query: CFTypeRef, result: *CFTypeRef) OSStatus;
extern fn SecItemDelete(query: CFTypeRef) OSStatus;

const Query = struct {
    service: CFTypeRef,
    account: CFTypeRef,
    data: CFTypeRef,
    dict: CFTypeRef,

    fn init(service: []const u8, account: []const u8, data: ?[]const u8, extra_key: CFTypeRef, extra_value: CFTypeRef) !Query {
        var q: Query = .{ .service = null, .account = null, .data = null, .dict = null };
        errdefer q.deinit();
        q.service = CFStringCreateWithBytes(null, service.ptr, @intCast(service.len), kCFStringEncodingUTF8, false) orelse return error.OutOfMemory;
        q.account = CFStringCreateWithBytes(null, account.ptr, @intCast(account.len), kCFStringEncodingUTF8, false) orelse return error.OutOfMemory;
        if (data) |d| q.data = CFDataCreate(null, d.ptr, @intCast(d.len)) orelse return error.OutOfMemory;

        var keys: [5]CFTypeRef = .{ kSecClass, kSecAttrService, kSecAttrAccount, null, null };
        var values: [5]CFTypeRef = .{ kSecClassGenericPassword, q.service, q.account, null, null };
        var n: usize = 3;
        if (q.data) |d| {
            keys[n] = kSecValueData;
            values[n] = d;
            n += 1;
        }
        if (extra_key) |k| {
            keys[n] = k;
            values[n] = extra_value;
            n += 1;
        }
        q.dict = CFDictionaryCreate(null, &keys, &values, @intCast(n), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) orelse return error.OutOfMemory;
        return q;
    }

    fn deinit(self: Query) void {
        if (self.dict) |d| CFRelease(d);
        if (self.data) |d| CFRelease(d);
        if (self.account) |a| CFRelease(a);
        if (self.service) |s| CFRelease(s);
    }
};

/// `false` when there is no such item. The blob must be exactly `out.len`.
pub fn load(service: []const u8, account: []const u8, out: []u8) !bool {
    const q = try Query.init(service, account, null, kSecReturnData, kCFBooleanTrue);
    defer q.deinit();
    var result: CFTypeRef = null;
    const status = SecItemCopyMatching(q.dict, &result);
    if (status == errSecItemNotFound) return false;
    if (status != 0) return keychainError(status);
    defer CFRelease(result);
    const len: usize = @intCast(CFDataGetLength(result));
    if (len != out.len) return error.VaultKeyCorrupt;
    @memcpy(out, CFDataGetBytePtr(result)[0..len]);
    return true;
}

/// Replaces any existing item, so a retry after a half-finished save
/// converges.
pub fn store(service: []const u8, account: []const u8, data: []const u8) !void {
    try delete(service, account);
    const q = try Query.init(service, account, data, null, null);
    defer q.deinit();
    const status = SecItemAdd(q.dict, null);
    if (status != 0) return keychainError(status);
}

pub fn delete(service: []const u8, account: []const u8) !void {
    const q = try Query.init(service, account, null, null, null);
    defer q.deinit();
    const status = SecItemDelete(q.dict);
    if (status != 0 and status != errSecItemNotFound) return keychainError(status);
}

fn keychainError(status: OSStatus) error{ KeychainDenied, KeychainFailed } {
    // errSecAuthFailed, errSecInteractionNotAllowed, errSecUserCanceled.
    return switch (status) {
        -25293, -25308, -128 => error.KeychainDenied,
        else => error.KeychainFailed,
    };
}
