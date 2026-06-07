const std = @import("std");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
const pbkdf2 = std.crypto.pwhash.pbkdf2;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const KEY_LEN = XChaCha20Poly1305.key_length;
pub const NONCE_LEN = XChaCha20Poly1305.nonce_length;
pub const TAG_LEN = XChaCha20Poly1305.tag_length;
pub const SALT_LEN = 16;
pub const ENC_MAGIC = "FELLAENC";
const PBKDF2_ROUNDS: u32 = 100_000;

/// Derive a 32-byte key from password + salt using PBKDF2-HMAC-SHA256
pub fn deriveKey(password: []const u8, salt: [SALT_LEN]u8) ![KEY_LEN]u8 {
    var key: [KEY_LEN]u8 = undefined;
    try pbkdf2(&key, password, &salt, PBKDF2_ROUNDS, HmacSha256);
    return key;
}

/// Encrypt plaintext with XChaCha20-Poly1305.
/// Returns: magic(8) || salt(16) || nonce(24) || ciphertext || tag(16)
pub fn encrypt(alloc: std.mem.Allocator, plaintext: []const u8, password: []const u8) ![]u8 {
    var salt: [SALT_LEN]u8 = undefined;
    _ = std.os.linux.getrandom(&salt, SALT_LEN, 0);

    var nonce: [NONCE_LEN]u8 = undefined;
    _ = std.os.linux.getrandom(&nonce, NONCE_LEN, 0);

    const key = try deriveKey(password, salt);

    const out_len = ENC_MAGIC.len + SALT_LEN + NONCE_LEN + plaintext.len + TAG_LEN;
    const out = try alloc.alloc(u8, out_len);
    errdefer alloc.free(out);

    @memcpy(out[0..ENC_MAGIC.len], ENC_MAGIC);
    @memcpy(out[ENC_MAGIC.len..][0..SALT_LEN], &salt);
    @memcpy(out[ENC_MAGIC.len + SALT_LEN..][0..NONCE_LEN], &nonce);

    const ct_start = ENC_MAGIC.len + SALT_LEN + NONCE_LEN;
    var tag: [TAG_LEN]u8 = undefined;
    XChaCha20Poly1305.encrypt(
        out[ct_start..][0..plaintext.len],
        &tag,
        plaintext,
        "",
        nonce,
        key,
    );

    @memcpy(out[ct_start + plaintext.len..][0..TAG_LEN], &tag);
    return out;
}

/// Decrypt a blob produced by encrypt().
pub fn decrypt(alloc: std.mem.Allocator, ciphertext: []const u8, password: []const u8) ![]u8 {
    if (ciphertext.len < ENC_MAGIC.len + SALT_LEN + NONCE_LEN + TAG_LEN) return error.TooShort;
    if (!std.mem.eql(u8, ciphertext[0..ENC_MAGIC.len], ENC_MAGIC)) return error.BadMagic;

    const salt = ciphertext[ENC_MAGIC.len..][0..SALT_LEN];
    const nonce = ciphertext[ENC_MAGIC.len + SALT_LEN..][0..NONCE_LEN];
    const ct_len = ciphertext.len - ENC_MAGIC.len - SALT_LEN - NONCE_LEN - TAG_LEN;
    const ct = ciphertext[ENC_MAGIC.len + SALT_LEN + NONCE_LEN..][0..ct_len];
    const tag = ciphertext[ENC_MAGIC.len + SALT_LEN + NONCE_LEN + ct_len..][0..TAG_LEN];

    const key = try deriveKey(password, salt.*);

    const out = try alloc.alloc(u8, ct_len);
    errdefer alloc.free(out);

    try XChaCha20Poly1305.decrypt(out, ct, tag.*, "", nonce.*, key);
    return out;
}
