//! VORTEX-256 Block Cipher — Rust port of vortex-cipher.ts
//!
//! 256-bit key, 128-bit block, 20-round Generalized Feistel Network.
//! Key-dependent S-boxes via affine transformation over GF(2).
//! AEAD mode: CTR + CBC-MAC.

use zeroize::Zeroize;

// ============================================================================
// Constants
// ============================================================================

pub const BLOCK_SIZE: usize = 16;
pub const KEY_SIZE: usize = 32;
pub const NUM_ROUNDS: usize = 20;
const BRANCH_SIZE: usize = 4;
const NUM_BRANCHES: usize = 4;
const SBOX_SIZE: usize = 256;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;

const ROUND_CONSTANTS: [u32; 20] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    0xcbbb9d5d, 0x629a292a, 0x9159015a, 0x152fecd8,
    0x67332667, 0x8eb44a87, 0xdb0c2e0d, 0x47b5481d,
    0x5566b4e1, 0x0bdc42fa, 0x3b243958, 0xee3be15c,
];

const SEED_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

// ============================================================================
// Low-level Utilities
// ============================================================================

#[inline(always)]
fn rotl32(x: u32, n: u32) -> u32 {
    x.rotate_left(n & 31)
}

#[inline(always)]
fn rotr32(x: u32, n: u32) -> u32 {
    x.rotate_right(n & 31)
}

#[inline(always)]
fn read_u32_be(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
}

#[inline(always)]
fn write_u32_be(buf: &mut [u8], offset: usize, val: u32) {
    let bytes = val.to_be_bytes();
    buf[offset..offset + 4].copy_from_slice(&bytes);
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ============================================================================
// GF(2) Matrix Operations
// ============================================================================

fn gf2_mat_vec_mul(matrix: &[u8; 8], vec: u8) -> u8 {
    let mut result = 0u8;
    for row in 0..8 {
        let mut dot = matrix[row] & vec;
        dot ^= dot >> 4;
        dot ^= dot >> 2;
        dot ^= dot >> 1;
        if dot & 1 != 0 {
            result |= 1 << (7 - row);
        }
    }
    result
}

fn gf2_mat_det(matrix: &[u8; 8]) -> u8 {
    let mut m = *matrix;

    for col in 0..8 {
        let bit: u8 = 1 << (7 - col);
        let mut pivot_row: Option<usize> = None;
        for row in col..8 {
            if m[row] & bit != 0 {
                pivot_row = Some(row);
                break;
            }
        }
        let pivot_row = match pivot_row {
            Some(r) => r,
            None => return 0,
        };

        if pivot_row != col {
            m.swap(col, pivot_row);
        }

        for row in 0..8 {
            if row != col && (m[row] & bit != 0) {
                m[row] ^= m[col];
            }
        }
    }
    1
}

// ============================================================================
// PRNG
// ============================================================================

struct PrngState {
    s0: u32, s1: u32, s2: u32, s3: u32,
    s4: u32, s5: u32, s6: u32, s7: u32,
}

impl PrngState {
    fn init(key: &[u8]) -> Self {
        PrngState {
            s0: read_u32_be(key, 0),
            s1: read_u32_be(key, 4),
            s2: read_u32_be(key, 8),
            s3: read_u32_be(key, 12),
            s4: read_u32_be(key, 16),
            s5: read_u32_be(key, 20),
            s6: read_u32_be(key, 24),
            s7: read_u32_be(key, 28),
        }
    }

    fn next(&mut self) -> u32 {
        self.s0 = (self.s0 ^ 0x9e3779b9).wrapping_mul(0x45d9f3b).wrapping_add(rotl32(self.s1, 7)) ^ self.s2;
        self.s1 = (self.s1 ^ 0x6a09e667).wrapping_mul(0x119de1f3).wrapping_add(rotl32(self.s2, 13)) ^ self.s3;
        self.s2 = (self.s2 ^ 0xbb67ae85).wrapping_mul(0x16a6b885).wrapping_add(rotl32(self.s3, 17)) ^ self.s4;
        self.s3 = (self.s3 ^ 0x3c6ef372).wrapping_mul(0x3b4d6fcd).wrapping_add(rotl32(self.s4, 23)) ^ self.s5;
        self.s4 = (self.s4 ^ 0xa54ff53a).wrapping_mul(0x5e9a3fff).wrapping_add(rotl32(self.s5, 5)) ^ self.s6;
        self.s5 = (self.s5 ^ 0x510e527f).wrapping_mul(0x7a2b14c9).wrapping_add(rotl32(self.s6, 11)) ^ self.s7;
        self.s6 = (self.s6 ^ 0x9b05688c).wrapping_mul(0x2f8c49a7).wrapping_add(rotl32(self.s7, 19)) ^ self.s0;
        self.s7 = (self.s7 ^ 0x1f83d9ab).wrapping_mul(0x6c5b8e27).wrapping_add(rotl32(self.s0, 29)) ^ self.s1;
        self.s0 ^ self.s4
    }
}

// ============================================================================
// S-Box Generation
// ============================================================================

fn generate_sbox(key: &[u8]) -> [u8; SBOX_SIZE] {
    let mut sbox = [0u8; SBOX_SIZE];
    let mut st = PrngState::init(key);

    // Warm up PRNG
    for _ in 0..32 {
        st.next();
    }

    // Generate invertible 8x8 matrix over GF(2)
    let mut matrix = [0u8; 8];
    let mut attempts = 0u32;
    loop {
        let w0 = st.next();
        let w1 = st.next();
        matrix[0] = (w0 >> 24) as u8;
        matrix[1] = (w0 >> 16) as u8;
        matrix[2] = (w0 >> 8) as u8;
        matrix[3] = w0 as u8;
        matrix[4] = (w1 >> 24) as u8;
        matrix[5] = (w1 >> 16) as u8;
        matrix[6] = (w1 >> 8) as u8;
        matrix[7] = w1 as u8;
        attempts += 1;
        if attempts > 1000 {
            // Safety fallback — identity matrix
            for i in 0..8 {
                matrix[i] = 1 << (7 - i);
            }
            break;
        }
        if gf2_mat_det(&matrix) != 0 {
            break;
        }
    }

    let affine_const = (st.next() & 0xff) as u8;

    // Apply: S'(x) = A * SEED_SBOX(x) XOR c
    for i in 0..SBOX_SIZE {
        sbox[i] = gf2_mat_vec_mul(&matrix, SEED_SBOX[i]) ^ affine_const;
    }

    sbox
}

fn generate_inv_sbox(sbox: &[u8; SBOX_SIZE]) -> [u8; SBOX_SIZE] {
    let mut inv = [0u8; SBOX_SIZE];
    for i in 0..SBOX_SIZE {
        inv[sbox[i] as usize] = i as u8;
    }
    inv
}

// ============================================================================
// Constant-time S-box lookup
// ============================================================================

fn ct_lookup_byte(table: &[u8], index: u8) -> u8 {
    let mut result = 0u8;
    for i in 0..table.len() {
        let diff = (i as u8) ^ index;
        // mask = 0xFF when diff==0, 0x00 otherwise
        let mask = ((((diff as u32) | (diff as u32).wrapping_neg()) >> 31).wrapping_sub(1)) as u8;
        result |= table[i] & mask;
    }
    result
}

fn ct_sub_word(w: u32, sbox: &[u8]) -> u32 {
    let b3 = ct_lookup_byte(sbox, (w >> 24) as u8);
    let b2 = ct_lookup_byte(sbox, (w >> 16) as u8);
    let b1 = ct_lookup_byte(sbox, (w >> 8) as u8);
    let b0 = ct_lookup_byte(sbox, w as u8);
    ((b3 as u32) << 24) | ((b2 as u32) << 16) | ((b1 as u32) << 8) | (b0 as u32)
}

#[inline(always)]
fn sub_word(w: u32, sbox: &[u8]) -> u32 {
    ct_sub_word(w, sbox)
}

// ============================================================================
// Key Schedule
// ============================================================================

fn sigma_word(w: u32, sbox: &[u8]) -> u32 {
    let a = sub_word(w, sbox);
    let b = sub_word(rotl32(w, 8), sbox);
    let c = sub_word(rotl32(w, 16), sbox);
    let d = sub_word(rotl32(w, 24), sbox);
    a ^ b ^ c ^ d
}

fn key_mix(a: u32, b: u32, rc: u32, sbox: &[u8]) -> u32 {
    let mut t = a.wrapping_mul(0x1b873593) ^ rotl32(b, 15);
    t = sub_word(t, sbox) ^ rc;
    t ^ rotl32(t, 7) ^ rotl32(t, 18)
}

pub struct VortexKeySchedule {
    pre_whitening: [u32; 4],
    post_whitening: [u32; 4],
    round_keys: [[u32; 4]; NUM_ROUNDS],
    sbox: [u8; SBOX_SIZE],
    inv_sbox: [u8; SBOX_SIZE],
}

impl Drop for VortexKeySchedule {
    fn drop(&mut self) {
        self.pre_whitening.zeroize();
        self.post_whitening.zeroize();
        for rk in &mut self.round_keys {
            rk.zeroize();
        }
        self.sbox.zeroize();
        self.inv_sbox.zeroize();
    }
}

pub fn expand_key(master_key: &[u8]) -> VortexKeySchedule {
    assert!(master_key.len() == KEY_SIZE, "VORTEX-256: key must be {} bytes", KEY_SIZE);

    let sbox = generate_sbox(master_key);
    let inv_sbox = generate_inv_sbox(&sbox);

    let mut mk = [0u32; 8];
    for i in 0..8 {
        mk[i] = read_u32_be(master_key, i * 4);
    }

    let mut w = [0u32; 96];
    for i in 0..8 {
        w[i] = mk[i];
    }

    let key_odd_const = (read_u32_be(master_key, 0) ^ read_u32_be(master_key, 16)) | 1;

    for i in 8..96 {
        let rc_idx = i % NUM_ROUNDS;
        let rc = ROUND_CONSTANTS[rc_idx];

        let mut t = w[i - 8];
        t ^= sigma_word(w[i - 1], &sbox);
        t = t.wrapping_mul(key_odd_const);
        t ^= rc ^ rotl32(rc, ((i as u32).wrapping_mul(7)) & 31);

        if i % 8 == 0 {
            t ^= key_mix(w[i - 1], w[i - 8], rc, &sbox);
        } else if i % 4 == 0 {
            t ^= rotl32(w[i - 3], 11) ^ rotl32(w[i - 5], 23);
        } else {
            t ^= rotl32(w[i - 2], 13);
        }

        w[i] = t;
    }

    let mut pre_whitening = [0u32; 4];
    let mut post_whitening = [0u32; 4];
    for i in 0..4 {
        pre_whitening[i] = w[8 + i];
        post_whitening[i] = w[12 + i];
    }

    let mut round_keys = [[0u32; 4]; NUM_ROUNDS];
    for r in 0..NUM_ROUNDS {
        for i in 0..4 {
            round_keys[r][i] = w[16 + r * 4 + i];
        }
    }

    mk.zeroize();
    w.zeroize();

    VortexKeySchedule {
        pre_whitening,
        post_whitening,
        round_keys,
        sbox,
        inv_sbox,
    }
}

// ============================================================================
// Round Function Components
// ============================================================================

#[inline(always)]
fn substitute_branch(branch: u32, sbox: &[u8]) -> u32 {
    sub_word(branch, sbox)
}

#[inline(always)]
fn permute_branch(branch: u32, branch_idx: usize) -> u32 {
    let shift = ((branch_idx & 3) * 8) as u32;
    if shift == 0 { branch } else { rotl32(branch, shift) }
}

#[inline(always)]
fn inv_permute_branch(branch: u32, branch_idx: usize) -> u32 {
    let shift = ((branch_idx & 3) * 8) as u32;
    if shift == 0 { branch } else { rotr32(branch, shift) }
}

fn f_function(x: u32, round_key_word: u32, round_const: u32, sbox: &[u8]) -> u32 {
    let mut t = x.wrapping_add(round_key_word);
    t = sub_word(t, sbox);
    t = t ^ rotl32(t, 5) ^ rotl32(t, 17);
    t ^= round_const;
    t = sub_word(t, sbox);
    t ^ rotr32(t, 11) ^ rotr32(t, 23)
}

fn mix_branches_final(b: &mut [u32; 4]) {
    // Phase 1: Sequential cascade
    b[1] = b[1] ^ rotl32(b[0], 1) ^ rotl32(b[0], 7);
    b[2] = b[2] ^ rotl32(b[1], 11) ^ rotl32(b[1], 19);
    b[3] = b[3] ^ rotl32(b[2], 5) ^ rotl32(b[2], 23);
    b[0] = b[0] ^ rotl32(b[3], 13) ^ rotl32(b[3], 29);

    // Phase 2: Cross-lane mixing
    b[2] = b[2] ^ rotl32(b[0], 3);
    b[3] = b[3] ^ rotl32(b[1], 17);
    b[0] = b[0] ^ rotl32(b[2], 9);
    b[1] = b[1] ^ rotl32(b[3], 25);
}

fn inv_mix_branches_final(b: &mut [u32; 4]) {
    // Inverse Phase 2
    b[1] = b[1] ^ rotl32(b[3], 25);
    b[0] = b[0] ^ rotl32(b[2], 9);
    b[3] = b[3] ^ rotl32(b[1], 17);
    b[2] = b[2] ^ rotl32(b[0], 3);

    // Inverse Phase 1
    b[0] = b[0] ^ rotl32(b[3], 13) ^ rotl32(b[3], 29);
    b[3] = b[3] ^ rotl32(b[2], 5) ^ rotl32(b[2], 23);
    b[2] = b[2] ^ rotl32(b[1], 11) ^ rotl32(b[1], 19);
    b[1] = b[1] ^ rotl32(b[0], 1) ^ rotl32(b[0], 7);
}

// ============================================================================
// Core Block Cipher
// ============================================================================

fn vortex_round(state: &mut [u32; 4], round_key: &[u32; 4], round_num: usize, sbox: &[u8]) {
    let rc = ROUND_CONSTANTS[round_num];

    // Generalized Feistel
    let f0 = f_function(state[0], round_key[0], rc, sbox);
    let f2 = f_function(state[2], round_key[1], rotl32(rc, 16), sbox);
    state[1] ^= f0;
    state[3] ^= f2;

    // Substitution on all branches
    for i in 0..NUM_BRANCHES {
        state[i] = substitute_branch(state[i], sbox);
    }

    // Byte permutation
    for i in 0..NUM_BRANCHES {
        state[i] = permute_branch(state[i], i);
    }

    // Inter-branch mixing
    mix_branches_final(state);

    // Key addition on branches 0, 2
    state[0] ^= round_key[2];
    state[2] ^= round_key[3];

    // Branch rotation (circular shift right by 1)
    let tmp = state[3];
    state[3] = state[2];
    state[2] = state[1];
    state[1] = state[0];
    state[0] = tmp;
}

fn vortex_inv_round(
    state: &mut [u32; 4],
    round_key: &[u32; 4],
    round_num: usize,
    inv_sbox: &[u8],
    sbox: &[u8],
) {
    let rc = ROUND_CONSTANTS[round_num];

    // Inverse branch rotation (circular shift left by 1)
    let tmp = state[0];
    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = tmp;

    // Key removal
    state[0] ^= round_key[2];
    state[2] ^= round_key[3];

    // Inverse inter-branch mixing
    inv_mix_branches_final(state);

    // Inverse byte permutation
    for i in 0..NUM_BRANCHES {
        state[i] = inv_permute_branch(state[i], i);
    }

    // Inverse substitution
    for i in 0..NUM_BRANCHES {
        state[i] = substitute_branch(state[i], inv_sbox);
    }

    // Inverse Feistel
    let f0 = f_function(state[0], round_key[0], rc, sbox);
    let f2 = f_function(state[2], round_key[1], rotl32(rc, 16), sbox);
    state[1] ^= f0;
    state[3] ^= f2;
}

pub fn encrypt_block(block: &[u8], ks: &VortexKeySchedule) -> [u8; BLOCK_SIZE] {
    assert!(block.len() == BLOCK_SIZE);

    let mut state = [0u32; NUM_BRANCHES];
    for i in 0..NUM_BRANCHES {
        state[i] = read_u32_be(block, i * BRANCH_SIZE);
    }

    for i in 0..NUM_BRANCHES {
        state[i] ^= ks.pre_whitening[i];
    }

    for r in 0..NUM_ROUNDS {
        vortex_round(&mut state, &ks.round_keys[r], r, &ks.sbox);
    }

    for i in 0..NUM_BRANCHES {
        state[i] ^= ks.post_whitening[i];
    }

    let mut out = [0u8; BLOCK_SIZE];
    for i in 0..NUM_BRANCHES {
        write_u32_be(&mut out, i * BRANCH_SIZE, state[i]);
    }
    out
}

pub fn decrypt_block(block: &[u8], ks: &VortexKeySchedule) -> [u8; BLOCK_SIZE] {
    assert!(block.len() == BLOCK_SIZE);

    let mut state = [0u32; NUM_BRANCHES];
    for i in 0..NUM_BRANCHES {
        state[i] = read_u32_be(block, i * BRANCH_SIZE);
    }

    for i in 0..NUM_BRANCHES {
        state[i] ^= ks.post_whitening[i];
    }

    for r in (0..NUM_ROUNDS).rev() {
        vortex_inv_round(&mut state, &ks.round_keys[r], r, &ks.inv_sbox, &ks.sbox);
    }

    for i in 0..NUM_BRANCHES {
        state[i] ^= ks.pre_whitening[i];
    }

    let mut out = [0u8; BLOCK_SIZE];
    for i in 0..NUM_BRANCHES {
        write_u32_be(&mut out, i * BRANCH_SIZE, state[i]);
    }
    out
}

// ============================================================================
// AEAD Mode — CTR + CBC-MAC
// ============================================================================

fn increment_counter(counter: &mut [u8; BLOCK_SIZE]) -> Result<(), &'static str> {
    let c = read_u32_be(counter, 12);
    if c == 0xFFFFFFFF {
        return Err("VORTEX-256: CTR counter overflow");
    }
    write_u32_be(counter, 12, c + 1);
    Ok(())
}

fn pad_block(data: &[u8], offset: usize) -> [u8; BLOCK_SIZE] {
    let mut block = [0u8; BLOCK_SIZE];
    let to_copy = std::cmp::min(data.len() - offset, BLOCK_SIZE);
    block[..to_copy].copy_from_slice(&data[offset..offset + to_copy]);
    block
}

fn compute_mac(
    ks: &VortexKeySchedule,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> [u8; TAG_SIZE] {
    let mut h = [0u8; BLOCK_SIZE];

    // Process AAD blocks
    let mut i = 0;
    while i < aad.len() {
        let block = pad_block(aad, i);
        let xored = xor_bytes(&h, &block);
        h = encrypt_block(&xored, ks);
        i += BLOCK_SIZE;
    }

    // Process ciphertext blocks
    i = 0;
    while i < ciphertext.len() {
        let block = pad_block(ciphertext, i);
        let xored = xor_bytes(&h, &block);
        h = encrypt_block(&xored, ks);
        i += BLOCK_SIZE;
    }

    // Length block: AAD bits (64-bit BE) || CT bits (64-bit BE)
    let mut len_block = [0u8; BLOCK_SIZE];
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    write_u32_be(&mut len_block, 0, (aad_bits >> 32) as u32);
    write_u32_be(&mut len_block, 4, aad_bits as u32);
    write_u32_be(&mut len_block, 8, (ct_bits >> 32) as u32);
    write_u32_be(&mut len_block, 12, ct_bits as u32);
    let xored = xor_bytes(&h, &len_block);
    h = encrypt_block(&xored, ks);

    // Tag mask: encrypt(nonce || 0x00000000)
    let mut tag_mask_input = [0u8; BLOCK_SIZE];
    tag_mask_input[..NONCE_SIZE].copy_from_slice(&nonce[..NONCE_SIZE]);
    let tag_mask = encrypt_block(&tag_mask_input, ks);

    let result = xor_bytes(&h, &tag_mask);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&result[..TAG_SIZE]);
    tag
}

pub fn aead_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_SIZE]), &'static str> {
    assert!(key.len() == KEY_SIZE);
    assert!(nonce.len() == NONCE_SIZE);

    let ks = expand_key(key);

    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut counter = [0u8; BLOCK_SIZE];
    counter[..NONCE_SIZE].copy_from_slice(nonce);
    write_u32_be(&mut counter, 12, 1);

    let mut i = 0;
    while i < plaintext.len() {
        let keystream_block = encrypt_block(&counter, &ks);
        let remaining = std::cmp::min(BLOCK_SIZE, plaintext.len() - i);
        for j in 0..remaining {
            ciphertext[i + j] = plaintext[i + j] ^ keystream_block[j];
        }
        increment_counter(&mut counter)?;
        i += BLOCK_SIZE;
    }

    let tag = compute_mac(&ks, nonce, aad, &ciphertext);
    Ok((ciphertext, tag))
}

pub fn aead_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Option<Vec<u8>>, &'static str> {
    assert!(key.len() == KEY_SIZE);
    assert!(nonce.len() == NONCE_SIZE);
    assert!(tag.len() == TAG_SIZE);

    let ks = expand_key(key);

    let expected_tag = compute_mac(&ks, nonce, aad, ciphertext);
    if !constant_time_equal(&expected_tag, tag) {
        return Ok(None);
    }

    let mut plaintext = vec![0u8; ciphertext.len()];
    let mut counter = [0u8; BLOCK_SIZE];
    counter[..NONCE_SIZE].copy_from_slice(nonce);
    write_u32_be(&mut counter, 12, 1);

    let mut i = 0;
    while i < ciphertext.len() {
        let keystream_block = encrypt_block(&counter, &ks);
        let remaining = std::cmp::min(BLOCK_SIZE, ciphertext.len() - i);
        for j in 0..remaining {
            plaintext[i + j] = ciphertext[i + j] ^ keystream_block[j];
        }
        increment_counter(&mut counter)?;
        i += BLOCK_SIZE;
    }

    Ok(Some(plaintext))
}

// ============================================================================
// Public API — Structs
// ============================================================================

pub struct Vortex256 {
    ks: VortexKeySchedule,
}

impl Vortex256 {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() == KEY_SIZE, "VORTEX-256: key must be {} bytes", KEY_SIZE);
        Vortex256 { ks: expand_key(key) }
    }

    pub fn encrypt_block(&self, plaintext: &[u8]) -> [u8; BLOCK_SIZE] {
        encrypt_block(plaintext, &self.ks)
    }

    pub fn decrypt_block(&self, ciphertext: &[u8]) -> [u8; BLOCK_SIZE] {
        decrypt_block(ciphertext, &self.ks)
    }
}

pub struct Vortex256AEAD {
    key: Vec<u8>,
    used_nonces: std::collections::HashSet<Vec<u8>>,
}

impl Vortex256AEAD {
    pub fn new(key: &[u8]) -> Self {
        assert!(key.len() == KEY_SIZE, "VORTEX-256: key must be {} bytes", KEY_SIZE);
        Vortex256AEAD {
            key: key.to_vec(),
            used_nonces: std::collections::HashSet::new(),
        }
    }

    pub fn seal(&mut self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.used_nonces.contains(nonce) {
            return Err("VORTEX-256: NONCE REUSE DETECTED");
        }
        self.used_nonces.insert(nonce.to_vec());
        let (ciphertext, tag) = aead_encrypt(&self.key, nonce, plaintext, aad)?;
        let mut result = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
        result.extend_from_slice(&ciphertext);
        result.extend_from_slice(&tag);
        Ok(result)
    }

    pub fn open(&self, nonce: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
        if sealed.len() < TAG_SIZE {
            return Ok(None);
        }
        let ciphertext = &sealed[..sealed.len() - TAG_SIZE];
        let tag = &sealed[sealed.len() - TAG_SIZE..];
        aead_decrypt(&self.key, nonce, ciphertext, tag, aad)
    }
}

impl Drop for Vortex256AEAD {
    fn drop(&mut self) {
        self.key.zeroize();
        self.used_nonces.clear();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tv1_zero_key_zero_pt() {
        let key = [0u8; 32];
        let pt = [0u8; 16];
        let ct = encrypt_block(&pt, &expand_key(&key));
        let expected = hex_to_bytes("6ff1ec17617b991a3b6274cf69adbaa7");
        assert_eq!(ct.to_vec(), expected, "TV1 failed");
    }

    #[test]
    fn test_tv2_ff_key_ff_pt() {
        let key = [0xffu8; 32];
        let pt = [0xffu8; 16];
        let ct = encrypt_block(&pt, &expand_key(&key));
        let expected = hex_to_bytes("13fd12f8c08252145fd866db37610a1a");
        assert_eq!(ct.to_vec(), expected, "TV2 failed");
    }

    #[test]
    fn test_tv3_sequential_key_pt() {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let mut pt = [0u8; 16];
        for i in 0..16u8 {
            pt[i as usize] = i.wrapping_mul(16).wrapping_add(i);
        }
        let ct = encrypt_block(&pt, &expand_key(&key));
        let expected = hex_to_bytes("22a0674c4a92652b8089dc0b21eaf45d");
        assert_eq!(ct.to_vec(), expected, "TV3 failed");
    }

    #[test]
    fn test_tv4_aead() {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = i as u8;
        }
        let mut nonce = [0u8; 12];
        for i in 0..12 {
            nonce[i] = i as u8;
        }
        let pt = b"VORTEX-256 test";
        let aad = b"header";
        let (ct, tag) = aead_encrypt(&key, &nonce, pt, aad).unwrap();
        let expected_ct = hex_to_bytes("b90e36e8eff99b1ccfd302a8ed6e0c");
        let expected_tag = hex_to_bytes("0877f150c44bc14a6899cd75424bf0da");
        assert_eq!(ct, expected_ct, "TV4 ciphertext mismatch");
        assert_eq!(tag.to_vec(), expected_tag, "TV4 tag mismatch");
    }

    #[test]
    fn test_sbox_zero_key() {
        let key = [0u8; 32];
        let sbox = generate_sbox(&key);
        let expected_prefix = hex_to_bytes("f1539e21551d4ed236b6a2c7eaba2aeb4c7a6d26b9bc6b012d9bb379adb4b8f4");
        assert_eq!(&sbox[..32], &expected_prefix[..], "S-box for zero key mismatch");
    }

    #[test]
    fn test_key_schedule_zero_key() {
        let key = [0u8; 32];
        let ks = expand_key(&key);
        assert_eq!(ks.pre_whitening, [0x3bbcf558, 0x9e1af072, 0x6c8765bc, 0x3b373033]);
        assert_eq!(ks.post_whitening, [0x50404723, 0xe0733b01, 0x7d1a3ef0, 0x78777cae]);
        assert_eq!(ks.round_keys[0], [0x76de1359, 0xf7a66357, 0xda403d28, 0xce0a1416]);
        assert_eq!(ks.round_keys[19], [0x2be0c717, 0xf997b0fc, 0x3eb83481, 0x97f281ee]);
    }

    #[test]
    fn test_block_roundtrip() {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = (i * 3 + 7) as u8;
        }
        let pt = b"Hello, VORTEX!!";
        let mut block = [0u8; 16];
        block[..15].copy_from_slice(pt);
        let ks = expand_key(&key);
        let ct = encrypt_block(&block, &ks);
        let dt = decrypt_block(&ct, &ks);
        assert_eq!(dt, block, "Block round-trip failed");
    }

    #[test]
    fn test_aead_roundtrip() {
        let mut key = [0u8; 32];
        for i in 0..32 {
            key[i] = (i * 5 + 13) as u8;
        }
        let nonce = [1u8; 12];
        let pt = b"AEAD round-trip test with some longer data to test multi-block";
        let aad = b"associated data";
        let (ct, tag) = aead_encrypt(&key, &nonce, pt, aad).unwrap();
        let result = aead_decrypt(&key, &nonce, &ct, &tag, aad).unwrap();
        assert_eq!(result.unwrap(), pt.to_vec(), "AEAD round-trip failed");
    }

    #[test]
    fn test_aead_tamper_detection() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let pt = b"tamper test";
        let aad = b"aad";
        let (mut ct, tag) = aead_encrypt(&key, &nonce, pt, aad).unwrap();
        ct[0] ^= 1; // tamper
        let result = aead_decrypt(&key, &nonce, &ct, &tag, aad).unwrap();
        assert!(result.is_none(), "Tampered ciphertext should fail auth");
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
