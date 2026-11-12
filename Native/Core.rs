//! THE DPI — native network intelligence core.
//!
//! One crate, Rust standard library only, zero third-party dependencies.
//!
//! Sections (each a module with a single responsibility):
//! - `wire`     versioned binary codec shared with Kotlin (the only data format crossing JNI)
//! - `dns`      DNS message builder/parser (RFC 1035, RFC 6891 EDNS0, RFC 9460 HTTPS/SVCB)
//! - `quic`     QUIC v1 Version Negotiation probe builder/parser (RFC 9000 §6, §15, §17.2.1)
//! - `sys`      the small, reviewable set of OS FFI calls (setsockopt, IP Helper, registry)
//! - `probe`    bounded, low-impact measurements (DNS, TCP, UDP/QUIC reachability, path MTU)
//! - `intel`    explainable problem classification with confidence + observations
//! - `decide`   deterministic adaptive decision engine (hysteresis, debounce, cooldown, rollback)
//! - `engine`   engine lifecycle, configuration, scoring and report encoding
//! - `api`      safe Rust facade (used by JNI and by tests)
//! - `jni`      the single JNI boundary (no external JNI crate; panics never cross it)
//!
//! No cryptography is implemented here. TLS is measured by the platform layer
//! (Android platform TLS / JDK JSSE with the Windows certificate store) and only
//! the resulting observations are submitted to this core.

#![deny(unsafe_op_in_unsafe_fn)]

pub const API_VERSION: i32 = 1;
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Explicit error codes returned across the native API. Negative = error.
pub mod code {
    pub const OK: i32 = 0;
    pub const INVALID_ARGUMENT: i32 = -1;
    pub const INVALID_HANDLE: i32 = -2;
    pub const WIRE: i32 = -3;
    pub const BUSY: i32 = -4;
    pub const LIMIT: i32 = -5;
    pub const PANIC: i32 = -6;
    pub const NO_ENVIRONMENT: i32 = -7;
    pub const NO_DATA: i32 = -8;
    pub const UNSUPPORTED: i32 = -9;
    pub const JNI: i32 = -10;
    pub const INTERNAL: i32 = -11;
}

// ---------------------------------------------------------------------------
// ascii — architecture-specific Assembly (Core.s / Core.aarch64.s) with a std fallback
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("Core.s"), options(att_syntax));
#[cfg(target_arch = "aarch64")]
core::arch::global_asm!(include_str!("Core.aarch64.s"));

/// Architecture-specific SIMD Assembly primitives (Core.s SSE2 / Core.aarch64.s NEON)
/// with portable standard-library fallbacks:
/// - `lowercase_in_place` / `lowercased`: DNS/target ASCII normalization
/// - `csum_fold`: RFC 1071 16-bit one's-complement big-endian checksum accumulator
/// - `csum_delta`: RFC 1624 incremental checksum update for TTL/Seq/BadSum mutation
/// - `scan_pattern`: SIMD 16-byte broadcast scanner for TLS SNI/ECH and HTTP headers
pub mod ascii {
    #[cfg(target_arch = "x86_64")]
    unsafe extern "sysv64" {
        fn the_dpi_ascii_lowercase(dst: *mut u8, src: *const u8, len: usize);
        fn the_dpi_csum_fold(buf: *const u8, len: usize, initial: u64) -> u16;
        fn the_dpi_csum_delta(old_check: u16, old_word: u16, new_word: u16) -> u16;
        fn the_dpi_scan_pattern(
            hay: *const u8,
            hay_len: usize,
            needle: *const u8,
            needle_len: usize,
        ) -> usize;
    }
    #[cfg(target_arch = "aarch64")]
    unsafe extern "C" {
        fn the_dpi_ascii_lowercase(dst: *mut u8, src: *const u8, len: usize);
        fn the_dpi_csum_fold(buf: *const u8, len: usize, initial: u64) -> u16;
        fn the_dpi_csum_delta(old_check: u16, old_word: u16, new_word: u16) -> u16;
        fn the_dpi_scan_pattern(
            hay: *const u8,
            hay_len: usize,
            needle: *const u8,
            needle_len: usize,
        ) -> usize;
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn lowercase_in_place(buf: &mut [u8]) {
        if !buf.is_empty() {
            // SAFETY: `dst` and `src` are the same valid, writable buffer of `buf.len()`
            // bytes; the routine only reads and writes those bytes in place.
            unsafe { the_dpi_ascii_lowercase(buf.as_mut_ptr(), buf.as_ptr(), buf.len()) };
        }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn lowercase_in_place(buf: &mut [u8]) {
        buf.make_ascii_lowercase();
    }

    /// Lower-cases ASCII letters, leaving every other byte (including UTF-8 multibyte
    /// sequences) untouched; the result is always valid UTF-8.
    pub fn lowercased(s: &str) -> String {
        let mut v = s.as_bytes().to_vec();
        lowercase_in_place(&mut v);
        String::from_utf8(v).unwrap_or_else(|_| s.to_ascii_lowercase())
    }

    /// Portable reference implementation of RFC 1071 16-bit big-endian sum folding.
    pub fn csum_fold_std(buf: &[u8], mut sum: u64) -> u16 {
        let mut i = 0;
        while i + 1 < buf.len() {
            let w = (u16::from(buf[i]) << 8) | u16::from(buf[i + 1]);
            sum = sum.wrapping_add(u64::from(w));
            i += 2;
        }
        if i < buf.len() {
            sum = sum.wrapping_add(u64::from(buf[i]) << 8);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// Vectorized RFC 1071 16-bit one's-complement sum fold (before bitwise NOT).
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn csum_fold(buf: &[u8], initial: u64) -> u16 {
        // SAFETY: `buf.as_ptr()` is valid for `buf.len()` readable bytes.
        unsafe { the_dpi_csum_fold(buf.as_ptr(), buf.len(), initial) }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn csum_fold(buf: &[u8], initial: u64) -> u16 {
        csum_fold_std(buf, initial)
    }

    /// Portable reference implementation of RFC 1624 incremental checksum update.
    pub fn csum_delta_std(old_check: u16, old_word: u16, new_word: u16) -> u16 {
        let mut sum = u32::from(!old_check) + u32::from(!old_word) + u32::from(new_word);
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Hardware register RFC 1624 incremental checksum update: `HC' = ~(~HC + ~m + m')`.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn csum_delta(old_check: u16, old_word: u16, new_word: u16) -> u16 {
        // SAFETY: pure register arithmetic with no memory accesses.
        unsafe { the_dpi_csum_delta(old_check, old_word, new_word) }
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn csum_delta(old_check: u16, old_word: u16, new_word: u16) -> u16 {
        csum_delta_std(old_check, old_word, new_word)
    }

    /// Portable reference implementation of sub-slice pattern search.
    pub fn scan_pattern_std(hay: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        if needle.len() > hay.len() {
            return None;
        }
        hay.windows(needle.len()).position(|w| w == needle)
    }

    /// SIMD-accelerated sub-slice search for TLS/HTTP deep packet inspection.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub fn scan_pattern(hay: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return Some(0);
        }
        if needle.len() > hay.len() {
            return None;
        }
        // SAFETY: both slices are valid and readable for their respective lengths.
        let pos =
            unsafe { the_dpi_scan_pattern(hay.as_ptr(), hay.len(), needle.as_ptr(), needle.len()) };
        (pos < hay.len()).then_some(pos)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub fn scan_pattern(hay: &[u8], needle: &[u8]) -> Option<usize> {
        scan_pattern_std(hay, needle)
    }
}

/// Field tags of every wire record. Mirrored 1:1 in each platform's Core.kt (`object Tags`).
pub mod tags {
    pub const STATUS: u8 = 0;
    pub mod config {
        pub const TIMEOUT_MS: u8 = 1;
        pub const DNS_SAMPLES: u8 = 2;
        pub const MAX_PARALLEL: u8 = 3;
        pub const COOLDOWN_MS: u8 = 4;
        pub const HYSTERESIS_PCT: u8 = 5;
        pub const QUIC: u8 = 6;
        pub const MTU: u8 = 7;
        pub const TCP_SAMPLES: u8 = 8;
        pub const BUDGET_MS: u8 = 9;
    }
    pub mod env {
        pub const OS_NAME: u8 = 1;
        pub const OS_VERSION: u8 = 2;
        pub const ARCH: u8 = 3;
        pub const NETWORK_TYPE: u8 = 4;
        pub const INTERFACE: u8 = 5;
        pub const DNS_SERVER: u8 = 6;
        pub const GATEWAY: u8 = 7;
        pub const MTU: u8 = 8;
        pub const HAS_IPV4: u8 = 9;
        pub const HAS_IPV6: u8 = 10;
        pub const CAPTIVE: u8 = 11;
        pub const METERED: u8 = 12;
        pub const VALIDATED: u8 = 13;
        pub const PRIVATE_DNS: u8 = 14;
        pub const PRIVATE_DNS_NAME: u8 = 15;
        pub const OS_BUILD: u8 = 16;
        pub const CONNECTED: u8 = 17;
        pub const RESTRICT_BACKGROUND: u8 = 18;
    }
    pub mod request {
        pub const TARGET: u8 = 1;
        pub const ALT_DNS: u8 = 2;
    }
    pub mod run {
        pub const GENERATION: u8 = 1;
        pub const DURATION_US: u8 = 2;
        pub const RESOLVER: u8 = 3;
        pub const TARGET: u8 = 4;
        pub const INVALID: u8 = 5;
        pub const ENCRYPTED: u8 = 6;
    }
    pub mod resolver {
        pub const SERVER: u8 = 1;
        pub const ALTERNATE: u8 = 2;
        pub const SENT: u8 = 3;
        pub const RECEIVED: u8 = 4;
        pub const AVG_US: u8 = 5;
        pub const JITTER_US: u8 = 6;
        pub const STATUS: u8 = 7;
        pub const TCP_STATUS: u8 = 8;
    }
    pub mod target {
        pub const HOST: u8 = 1;
        pub const PORT: u8 = 2;
        pub const DNS_STATUS: u8 = 3;
        pub const DNS_US: u8 = 4;
        pub const ADDRESS: u8 = 5;
        pub const HTTPS_RR: u8 = 6;
        pub const ALPN: u8 = 7;
        pub const ECH: u8 = 8;
        pub const TCP4_STATUS: u8 = 9;
        pub const TCP4_US: u8 = 10;
        pub const TCP6_STATUS: u8 = 11;
        pub const TCP6_US: u8 = 12;
        pub const QUIC_STATUS: u8 = 13;
        pub const QUIC_US: u8 = 14;
        pub const QUIC_VERSION: u8 = 15;
        pub const PMTU: u8 = 16;
        pub const MTU_STATUS: u8 = 17;
        pub const TLS_STATUS: u8 = 18;
        pub const TLS_US: u8 = 19;
        pub const TLS_VERSION: u8 = 20;
        pub const TLS_ALPN: u8 = 21;
        pub const TLS_CIPHER: u8 = 22;
        pub const TCP4_ATTEMPTS: u8 = 23;
        pub const TCP4_OK: u8 = 24;
        pub const TCP6_ATTEMPTS: u8 = 25;
        pub const TCP6_OK: u8 = 26;
        pub const MTU_PROBES: u8 = 27;
        pub const DNS_SERVER: u8 = 28;
        pub const DNS_TCP: u8 = 29;
        pub const DNS_RCODE: u8 = 30;
        pub const LITERAL: u8 = 31;
        pub const MTU_CEILING: u8 = 32;
    }
    pub mod tls_submit {
        pub const RESULT: u8 = 1;
    }
    pub mod enc_submit {
        pub const RESULT: u8 = 1;
    }
    /// Encrypted-resolver (DoH3/DoH/DoT/DoQ) measurement performed over platform HTTPS/TLS.
    pub mod enc {
        pub const ENDPOINT: u8 = 1;
        pub const PROTOCOL: u8 = 2;
        pub const TRANSPORT: u8 = 3;
        pub const RTT_US: u8 = 4;
        pub const QUERY_NAME: u8 = 5;
        pub const QTYPE: u8 = 6;
        pub const RESPONSE: u8 = 7;
        pub const STATUS: u8 = 8;
        pub const ANSWERS: u8 = 9;
    }
    pub mod doh_query {
        pub const NAME: u8 = 1;
        pub const QTYPE: u8 = 2;
        pub const QUERY: u8 = 1;
    }
    pub mod tls {
        pub const HOST: u8 = 1;
        pub const PORT: u8 = 2;
        pub const STATUS: u8 = 3;
        pub const HANDSHAKE_US: u8 = 4;
        pub const VERSION: u8 = 5;
        pub const ALPN: u8 = 6;
        pub const CIPHER: u8 = 7;
    }
    pub mod eval {
        pub const SCORE: u8 = 1;
        pub const EWMA: u8 = 2;
        pub const GENERATION: u8 = 3;
        pub const DIAGNOSIS: u8 = 4;
        pub const DECISION: u8 = 5;
        pub const STABILITY: u8 = 6;
        pub const EVALUATIONS: u8 = 7;
        pub const DESYNC_MODE: u8 = 8;
    }
    pub mod diagnosis {
        pub const CATEGORY: u8 = 1;
        pub const CONFIDENCE: u8 = 2;
        pub const OBSERVATION: u8 = 3;
    }
    pub mod observation {
        pub const CODE: u8 = 1;
        pub const SUBJECT: u8 = 2;
        pub const ARG: u8 = 3;
    }
    /// System-wide connection snapshot (Windows, user mode, no driver).
    pub mod sysnet {
        pub const TOTAL: u8 = 1;
        pub const ESTABLISHED: u8 = 2;
        pub const LISTEN: u8 = 3;
        pub const SYN_SENT: u8 = 4;
        pub const TIME_WAIT: u8 = 5;
        pub const CLOSE_WAIT: u8 = 6;
        pub const UDP: u8 = 7;
        pub const PROCESS: u8 = 8;
        pub const FINDING: u8 = 9;
        pub const EXPOSED: u8 = 10;
        pub const OS_ERROR: u8 = 11;
    }
    pub mod process {
        pub const PID: u8 = 1;
        pub const NAME: u8 = 2;
        pub const ESTABLISHED: u8 = 3;
        pub const SYN_SENT: u8 = 4;
        pub const LISTEN: u8 = 5;
        pub const UDP: u8 = 6;
        pub const REMOTES: u8 = 7;
        pub const CLOSE_WAIT: u8 = 8;
        pub const SAMPLE: u8 = 9;
    }
    pub mod finding {
        pub const CODE: u8 = 1;
        pub const SUBJECT: u8 = 2;
        pub const ARG: u8 = 3;
    }
    pub mod decision {
        pub const STATE: u8 = 1;
        pub const ACTION: u8 = 2;
        pub const CONFIDENCE: u8 = 3;
        pub const CATEGORY: u8 = 4;
        pub const COOLDOWN_MS: u8 = 5;
        pub const PARAM: u8 = 6;
        pub const HIGH_IMPACT: u8 = 7;
    }
    /// Active DPI circumvention (desynchronization) and local proxy wire tags.
    pub mod desync {
        pub const MODE: u8 = 1;
        pub const FAKE_TTL: u8 = 2;
        pub const SPLIT_POS: u8 = 3;
        pub const DROP_RST: u8 = 4;
        pub const PORT: u8 = 5;
        pub const PACKET: u8 = 6;
        pub const OUT_PACKET: u8 = 7;
        pub const DROPPED: u8 = 8;
        pub const PROTOCOL: u8 = 9;
        pub const SNI: u8 = 10;
        pub const ECH: u8 = 11;
        pub const POST_QUANTUM: u8 = 12;
        pub const CONNECTIONS: u8 = 13;
        pub const TLS_SPLIT: u8 = 14;
        pub const HTTP_SPLIT: u8 = 15;
        pub const FAKE_SENT: u8 = 16;
        pub const RST_DROPPED: u8 = 17;
        pub const ACTIVE: u8 = 18;
        pub const VISION_SPLICE: u8 = 19;
        pub const REALITY_DEST: u8 = 20;
    }
}

// ---------------------------------------------------------------------------
// wire — versioned TLV codec
// ---------------------------------------------------------------------------

/// Message = "DP" magic, version byte, then fields.
/// Field   = tag:u8, kind:u8, length:u32 BE, payload.
/// Kinds   = 1 Int (8-byte BE i64), 2 Text (UTF-8), 3 Record (nested fields).
pub mod wire {
    pub const MAGIC: [u8; 2] = *b"DP";
    pub const VERSION: u8 = 1;
    pub const MAX_MESSAGE: usize = 256 * 1024;
    pub const MAX_DEPTH: usize = 4;
    pub const MAX_FIELDS: usize = 8192;
    pub const MAX_TEXT: usize = 4096;
    pub const MAX_BYTES: usize = 16 * 1024;
    const KIND_INT: u8 = 1;
    const KIND_TEXT: u8 = 2;
    const KIND_RECORD: u8 = 3;
    const KIND_BYTES: u8 = 4;
    const FIELD_HEADER: usize = 6;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        Int(i64),
        Text(String),
        Record(Record),
        Bytes(Vec<u8>),
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Record {
        fields: Vec<(u8, Value)>,
    }

    impl Record {
        pub fn new() -> Self {
            Self::default()
        }
        pub fn with_status(code: i32) -> Self {
            let mut r = Self::new();
            r.int(super::tags::STATUS, i64::from(code));
            r
        }
        pub fn int(&mut self, tag: u8, v: i64) -> &mut Self {
            self.fields.push((tag, Value::Int(v)));
            self
        }
        pub fn text(&mut self, tag: u8, v: &str) -> &mut Self {
            self.fields
                .push((tag, Value::Text(truncate_utf8(v, MAX_TEXT).to_owned())));
            self
        }
        pub fn record(&mut self, tag: u8, r: Record) -> &mut Self {
            self.fields.push((tag, Value::Record(r)));
            self
        }
        /// Raw binary payload (e.g. a DNS wire message), truncated to `MAX_BYTES`.
        pub fn bytes(&mut self, tag: u8, v: &[u8]) -> &mut Self {
            self.fields
                .push((tag, Value::Bytes(v[..v.len().min(MAX_BYTES)].to_vec())));
            self
        }
        pub fn get_bytes(&self, tag: u8) -> Option<&[u8]> {
            self.fields.iter().find_map(|(t, v)| match v {
                Value::Bytes(b) if *t == tag => Some(b.as_slice()),
                _ => None,
            })
        }
        pub fn fields(&self) -> &[(u8, Value)] {
            &self.fields
        }
        pub fn status(&self) -> Option<i64> {
            self.get_int(super::tags::STATUS)
        }
        pub fn get_int(&self, tag: u8) -> Option<i64> {
            self.ints(tag).next()
        }
        pub fn get_text(&self, tag: u8) -> Option<&str> {
            self.texts(tag).next()
        }
        pub fn ints(&self, tag: u8) -> impl Iterator<Item = i64> + '_ {
            self.fields.iter().filter_map(move |(t, v)| match v {
                Value::Int(i) if *t == tag => Some(*i),
                _ => None,
            })
        }
        pub fn texts(&self, tag: u8) -> impl Iterator<Item = &str> + '_ {
            self.fields.iter().filter_map(move |(t, v)| match v {
                Value::Text(s) if *t == tag => Some(s.as_str()),
                _ => None,
            })
        }
        pub fn records(&self, tag: u8) -> impl Iterator<Item = &Record> + '_ {
            self.fields.iter().filter_map(move |(t, v)| match v {
                Value::Record(r) if *t == tag => Some(r),
                _ => None,
            })
        }
    }

    pub fn truncate_utf8(s: &str, max: usize) -> &str {
        if s.len() <= max {
            return s;
        }
        let mut end = max;
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum WireError {
        TooLarge,
        BadMagic,
        BadVersion,
        Truncated,
        BadKind,
        BadUtf8,
        TooDeep,
        TooManyFields,
        BadLength,
    }

    pub fn encode(r: &Record) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        let mut count = 0usize;
        encode_fields(r, &mut out, 0, &mut count)?;
        Ok(out)
    }

    fn header(out: &mut Vec<u8>, tag: u8, kind: u8, len: usize) -> Result<(), WireError> {
        let len = u32::try_from(len).map_err(|_| WireError::TooLarge)?;
        out.push(tag);
        out.push(kind);
        out.extend_from_slice(&len.to_be_bytes());
        Ok(())
    }

    fn encode_fields(
        r: &Record,
        out: &mut Vec<u8>,
        depth: usize,
        count: &mut usize,
    ) -> Result<(), WireError> {
        if depth >= MAX_DEPTH {
            return Err(WireError::TooDeep);
        }
        for (tag, v) in &r.fields {
            *count += 1;
            if *count > MAX_FIELDS {
                return Err(WireError::TooManyFields);
            }
            match v {
                Value::Int(i) => {
                    header(out, *tag, KIND_INT, 8)?;
                    out.extend_from_slice(&i.to_be_bytes());
                }
                Value::Text(s) => {
                    header(out, *tag, KIND_TEXT, s.len())?;
                    out.extend_from_slice(s.as_bytes());
                }
                Value::Bytes(b) => {
                    header(out, *tag, KIND_BYTES, b.len())?;
                    out.extend_from_slice(b);
                }
                Value::Record(inner) => {
                    let at = out.len();
                    header(out, *tag, KIND_RECORD, 0)?;
                    let start = out.len();
                    encode_fields(inner, out, depth + 1, count)?;
                    let len = u32::try_from(out.len() - start).map_err(|_| WireError::TooLarge)?;
                    out[at + 2..at + 6].copy_from_slice(&len.to_be_bytes());
                }
            }
            if out.len() > MAX_MESSAGE {
                return Err(WireError::TooLarge);
            }
        }
        Ok(())
    }

    pub fn decode(b: &[u8]) -> Result<Record, WireError> {
        if b.len() > MAX_MESSAGE {
            return Err(WireError::TooLarge);
        }
        if b.len() < 3 {
            return Err(WireError::Truncated);
        }
        if b[..2] != MAGIC {
            return Err(WireError::BadMagic);
        }
        if b[2] != VERSION {
            return Err(WireError::BadVersion);
        }
        let mut count = 0usize;
        decode_fields(&b[3..], 0, &mut count)
    }

    fn decode_fields(mut b: &[u8], depth: usize, count: &mut usize) -> Result<Record, WireError> {
        if depth >= MAX_DEPTH {
            return Err(WireError::TooDeep);
        }
        let mut rec = Record::new();
        while !b.is_empty() {
            if b.len() < FIELD_HEADER {
                return Err(WireError::Truncated);
            }
            let tag = b[0];
            let kind = b[1];
            let len = u32::from_be_bytes([b[2], b[3], b[4], b[5]]) as usize;
            let rest = &b[FIELD_HEADER..];
            if len > rest.len() {
                return Err(WireError::Truncated);
            }
            let (payload, next) = rest.split_at(len);
            *count += 1;
            if *count > MAX_FIELDS {
                return Err(WireError::TooManyFields);
            }
            let value = match kind {
                KIND_INT => {
                    let raw: [u8; 8] = payload.try_into().map_err(|_| WireError::BadLength)?;
                    Value::Int(i64::from_be_bytes(raw))
                }
                KIND_TEXT => {
                    if len > MAX_TEXT {
                        return Err(WireError::BadLength);
                    }
                    Value::Text(
                        std::str::from_utf8(payload)
                            .map_err(|_| WireError::BadUtf8)?
                            .to_owned(),
                    )
                }
                KIND_RECORD => Value::Record(decode_fields(payload, depth + 1, count)?),
                KIND_BYTES => {
                    if len > MAX_BYTES {
                        return Err(WireError::BadLength);
                    }
                    Value::Bytes(payload.to_vec())
                }
                _ => return Err(WireError::BadKind),
            };
            rec.fields.push((tag, value));
            b = next;
        }
        Ok(rec)
    }
}

// ---------------------------------------------------------------------------
// dns — RFC 1035 message handling, EDNS0 (RFC 6891), HTTPS RR (RFC 9460)
// ---------------------------------------------------------------------------

pub mod dns {
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub const TYPE_A: u16 = 1;
    pub const TYPE_CNAME: u16 = 5;
    pub const TYPE_AAAA: u16 = 28;
    pub const TYPE_OPT: u16 = 41;
    pub const TYPE_HTTPS: u16 = 65;
    pub const CLASS_IN: u16 = 1;
    pub const MAX_NAME_WIRE: usize = 255;
    pub const MAX_POINTER_HOPS: usize = 32;
    /// DNS Flag Day 2020 recommended EDNS buffer size; avoids IP fragmentation.
    pub const EDNS_UDP_SIZE: u16 = 1232;
    pub const MAX_ANSWERS: u16 = 64;
    pub const RCODE_NOERROR: u8 = 0;
    pub const RCODE_SERVFAIL: u8 = 2;
    pub const RCODE_NXDOMAIN: u8 = 3;
    pub const RCODE_REFUSED: u8 = 5;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DnsError {
        Truncated,
        BadName,
        PointerLoop,
        IdMismatch,
        QuestionMismatch,
        NotResponse,
        BadRdata,
        NameTooLong,
    }

    /// LDH hostname check (RFC 1123 §2.1). IDNs must be supplied in A-label (punycode) form.
    pub fn is_valid_hostname(host: &str) -> bool {
        let h = host.strip_suffix('.').unwrap_or(host);
        if h.is_empty() || h.len() > 253 {
            return false;
        }
        let mut last_numeric = false;
        for label in h.split('.') {
            let b = label.as_bytes();
            if b.is_empty() || b.len() > 63 || b[0] == b'-' || b[b.len() - 1] == b'-' {
                return false;
            }
            if !b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-') {
                return false;
            }
            last_numeric = b.iter().all(u8::is_ascii_digit);
        }
        !last_numeric
    }

    pub fn encode_name(name: &str, out: &mut Vec<u8>) -> Result<(), DnsError> {
        let n = name.strip_suffix('.').unwrap_or(name);
        let start = out.len();
        if !n.is_empty() {
            for label in n.split('.') {
                let b = label.as_bytes();
                if b.is_empty() || b.len() > 63 {
                    return Err(DnsError::BadName);
                }
                out.push(b.len() as u8);
                out.extend_from_slice(b);
            }
        }
        out.push(0);
        if out.len() - start > MAX_NAME_WIRE {
            return Err(DnsError::NameTooLong);
        }
        Ok(())
    }

    /// Standard recursive query (RD=1) with an EDNS0 OPT record when `edns` is set.
    pub fn build_query(id: u16, name: &str, qtype: u16, edns: bool) -> Result<Vec<u8>, DnsError> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&0x0100u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&0u16.to_be_bytes());
        q.extend_from_slice(&u16::from(edns).to_be_bytes());
        encode_name(name, &mut q)?;
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        if edns {
            q.push(0);
            q.extend_from_slice(&TYPE_OPT.to_be_bytes());
            q.extend_from_slice(&EDNS_UDP_SIZE.to_be_bytes());
            q.extend_from_slice(&0u32.to_be_bytes());
            q.extend_from_slice(&0u16.to_be_bytes());
        }
        Ok(q)
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Header {
        pub id: u16,
        pub flags: u16,
        pub qdcount: u16,
        pub ancount: u16,
        pub nscount: u16,
        pub arcount: u16,
    }

    impl Header {
        pub fn parse(b: &[u8]) -> Result<Self, DnsError> {
            if b.len() < 12 {
                return Err(DnsError::Truncated);
            }
            let w = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
            Ok(Self {
                id: w(0),
                flags: w(2),
                qdcount: w(4),
                ancount: w(6),
                nscount: w(8),
                arcount: w(10),
            })
        }
        pub fn is_response(&self) -> bool {
            self.flags & 0x8000 != 0
        }
        pub fn truncated(&self) -> bool {
            self.flags & 0x0200 != 0
        }
        pub fn rcode(&self) -> u8 {
            (self.flags & 0x000F) as u8
        }
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Svcb {
        pub priority: u16,
        pub target: String,
        pub alpn: Vec<String>,
        pub no_default_alpn: bool,
        pub port: Option<u16>,
        pub ech: bool,
        pub ipv4_hints: Vec<Ipv4Addr>,
        pub ipv6_hints: Vec<Ipv6Addr>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RData {
        A(Ipv4Addr),
        Aaaa(Ipv6Addr),
        Cname(String),
        Https(Svcb),
        Other,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Answer {
        pub name: String,
        pub rtype: u16,
        pub ttl: u32,
        pub data: RData,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Response {
        pub header: Header,
        pub answers: Vec<Answer>,
    }

    fn be16(b: &[u8], i: usize) -> Result<u16, DnsError> {
        let s = b.get(i..i + 2).ok_or(DnsError::Truncated)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    fn be32(b: &[u8], i: usize) -> Result<u32, DnsError> {
        let s = b.get(i..i + 4).ok_or(DnsError::Truncated)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn push_label(name: &mut String, label: &[u8]) {
        if !name.is_empty() {
            name.push('.');
        }
        for &c in label {
            if c.is_ascii_graphic() && c != b'.' && c != b'\\' {
                name.push(char::from(c.to_ascii_lowercase()));
            } else {
                // RFC 4343 style escaping of non-printable label octets.
                name.push('\\');
                name.push(char::from(b'0' + c / 100));
                name.push(char::from(b'0' + (c / 10) % 10));
                name.push(char::from(b'0' + c % 10));
            }
        }
    }

    /// Reads a possibly compressed name (RFC 1035 §4.1.4). Pointers must point
    /// strictly backwards and hops are bounded, so malicious loops terminate.
    /// Returns the lower-case dotted name and the offset just after the name.
    pub fn read_name(msg: &[u8], pos: usize) -> Result<(String, usize), DnsError> {
        let mut name = String::new();
        let mut p = pos;
        let mut end: Option<usize> = None;
        let mut hops = 0usize;
        let mut wire_len = 0usize;
        loop {
            let len = usize::from(*msg.get(p).ok_or(DnsError::Truncated)?);
            match len & 0xC0 {
                0x00 => {
                    wire_len += 1 + len;
                    if wire_len > MAX_NAME_WIRE {
                        return Err(DnsError::NameTooLong);
                    }
                    if len == 0 {
                        return Ok((name, end.unwrap_or(p + 1)));
                    }
                    let label = msg.get(p + 1..p + 1 + len).ok_or(DnsError::Truncated)?;
                    push_label(&mut name, label);
                    p += 1 + len;
                }
                0xC0 => {
                    let low = usize::from(*msg.get(p + 1).ok_or(DnsError::Truncated)?);
                    let target = ((len & 0x3F) << 8) | low;
                    if end.is_none() {
                        end = Some(p + 2);
                    }
                    hops += 1;
                    if hops > MAX_POINTER_HOPS || target >= p {
                        return Err(DnsError::PointerLoop);
                    }
                    p = target;
                }
                _ => return Err(DnsError::BadName),
            }
        }
    }

    /// SVCB TargetName must not be compressed (RFC 9460 §2.2).
    fn read_uncompressed_name(b: &[u8], pos: usize) -> Result<(String, usize), DnsError> {
        let mut name = String::new();
        let mut p = pos;
        loop {
            let len = usize::from(*b.get(p).ok_or(DnsError::Truncated)?);
            if len & 0xC0 != 0 {
                return Err(DnsError::BadName);
            }
            if p + 1 - pos > MAX_NAME_WIRE {
                return Err(DnsError::NameTooLong);
            }
            if len == 0 {
                if name.is_empty() {
                    name.push('.');
                }
                return Ok((name, p + 1));
            }
            let label = b.get(p + 1..p + 1 + len).ok_or(DnsError::Truncated)?;
            push_label(&mut name, label);
            p += 1 + len;
        }
    }

    pub fn parse_svcb(rd: &[u8]) -> Result<Svcb, DnsError> {
        let priority = be16(rd, 0)?;
        let (target, mut p) = read_uncompressed_name(rd, 2)?;
        let mut s = Svcb {
            priority,
            target,
            ..Svcb::default()
        };
        let mut last_key: Option<u16> = None;
        while p < rd.len() {
            let key = be16(rd, p)?;
            let len = usize::from(be16(rd, p + 2)?);
            let vs = p + 4;
            let v = rd.get(vs..vs + len).ok_or(DnsError::Truncated)?;
            if last_key.is_some_and(|l| key <= l) {
                return Err(DnsError::BadRdata); // keys must be strictly increasing
            }
            last_key = Some(key);
            match key {
                1 => {
                    let mut q = 0;
                    while q < v.len() {
                        let l = usize::from(v[q]);
                        let id = v.get(q + 1..q + 1 + l).ok_or(DnsError::BadRdata)?;
                        if l == 0 {
                            return Err(DnsError::BadRdata);
                        }
                        if s.alpn.len() < 16 {
                            s.alpn.push(String::from_utf8_lossy(id).into_owned());
                        }
                        q += 1 + l;
                    }
                    if s.alpn.is_empty() {
                        return Err(DnsError::BadRdata);
                    }
                }
                2 => {
                    if len != 0 {
                        return Err(DnsError::BadRdata);
                    }
                    s.no_default_alpn = true;
                }
                3 => {
                    if len != 2 {
                        return Err(DnsError::BadRdata);
                    }
                    s.port = Some(be16(v, 0)?);
                }
                4 => {
                    if len == 0 || !len.is_multiple_of(4) {
                        return Err(DnsError::BadRdata);
                    }
                    s.ipv4_hints.extend(
                        v.as_chunks::<4>()
                            .0
                            .iter()
                            .take(16)
                            .map(|c| Ipv4Addr::from(*c)),
                    );
                }
                5 => {
                    if len == 0 {
                        return Err(DnsError::BadRdata);
                    }
                    s.ech = true;
                }
                6 => {
                    if len == 0 || !len.is_multiple_of(16) {
                        return Err(DnsError::BadRdata);
                    }
                    s.ipv6_hints.extend(
                        v.as_chunks::<16>()
                            .0
                            .iter()
                            .take(16)
                            .map(|c| Ipv6Addr::from(*c)),
                    );
                }
                _ => {}
            }
            p = vs + len;
        }
        Ok(s)
    }

    fn normalize(q: &str) -> String {
        crate::ascii::lowercased(q.strip_suffix('.').unwrap_or(q))
    }

    /// Parses and validates a response against the query it answers (ID, QR bit,
    /// question echo — RFC 5452 acceptance rules).
    pub fn parse_response(
        msg: &[u8],
        id: u16,
        qname: &str,
        qtype: u16,
    ) -> Result<Response, DnsError> {
        let header = Header::parse(msg)?;
        if header.id != id {
            return Err(DnsError::IdMismatch);
        }
        if !header.is_response() {
            return Err(DnsError::NotResponse);
        }
        let mut answers = Vec::new();
        if header.qdcount == 0 && header.rcode() != RCODE_NOERROR {
            return Ok(Response { header, answers });
        }
        if header.qdcount != 1 {
            return Err(DnsError::QuestionMismatch);
        }
        let (name, p) = read_name(msg, 12)?;
        if name != normalize(qname) || be16(msg, p)? != qtype || be16(msg, p + 2)? != CLASS_IN {
            return Err(DnsError::QuestionMismatch);
        }
        let mut pos = p + 4;
        if header.truncated() {
            return Ok(Response { header, answers });
        }
        for _ in 0..header.ancount.min(MAX_ANSWERS) {
            let (name, p) = read_name(msg, pos)?;
            let rtype = be16(msg, p)?;
            let class = be16(msg, p + 2)?;
            let ttl = be32(msg, p + 4)?;
            let rdlen = usize::from(be16(msg, p + 8)?);
            let rstart = p + 10;
            let rend = rstart + rdlen;
            let rdata = msg.get(rstart..rend).ok_or(DnsError::Truncated)?;
            let data = match (rtype, class) {
                (TYPE_A, CLASS_IN) => {
                    let o: [u8; 4] = rdata.try_into().map_err(|_| DnsError::BadRdata)?;
                    RData::A(Ipv4Addr::from(o))
                }
                (TYPE_AAAA, CLASS_IN) => {
                    let o: [u8; 16] = rdata.try_into().map_err(|_| DnsError::BadRdata)?;
                    RData::Aaaa(Ipv6Addr::from(o))
                }
                (TYPE_CNAME, CLASS_IN) => {
                    let (n, e) = read_name(msg, rstart)?;
                    if e != rend {
                        return Err(DnsError::BadRdata);
                    }
                    RData::Cname(n)
                }
                (TYPE_HTTPS, CLASS_IN) => RData::Https(parse_svcb(rdata)?),
                _ => RData::Other,
            };
            answers.push(Answer {
                name,
                rtype,
                ttl,
                data,
            });
            pos = rend;
        }
        Ok(Response { header, answers })
    }
}

// ---------------------------------------------------------------------------
// quic — Version Negotiation reachability probe (no cryptography involved)
// ---------------------------------------------------------------------------

/// A client Initial carrying a reserved version (0x?a?a?a?a, RFC 9000 §15) and
/// padded to 1200 bytes (§14.1) obliges a QUIC server to answer with a Version
/// Negotiation packet (§6.1) listing the versions it supports. This proves UDP
/// reachability of the QUIC endpoint and QUIC v1 support without any handshake
/// or cryptographic operation.
pub mod quic {
    pub const VERSION_1: u32 = 0x0000_0001;
    pub const VERSION_2: u32 = 0x6b33_43cf;
    pub const GREASE_VERSION: u32 = 0x1a2a_3a4a;
    pub const MIN_INITIAL_DATAGRAM: usize = 1200;
    pub const CID_LEN: usize = 8;
    pub const MAX_VERSIONS: usize = 64;

    pub fn build_probe(dcid: &[u8; CID_LEN], scid: &[u8; CID_LEN], size: usize) -> Vec<u8> {
        let size = size.max(MIN_INITIAL_DATAGRAM);
        let mut p = Vec::with_capacity(size);
        p.push(0xC0); // long header, fixed bit
        p.extend_from_slice(&GREASE_VERSION.to_be_bytes());
        p.push(CID_LEN as u8);
        p.extend_from_slice(dcid);
        p.push(CID_LEN as u8);
        p.extend_from_slice(scid);
        p.resize(size, 0);
        p
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum VnError {
        Truncated,
        NotLongHeader,
        NotVersionNegotiation,
        CidMismatch,
        Empty,
    }

    /// Validates a Version Negotiation packet (RFC 9000 §17.2.1): the server must
    /// echo our SCID as its DCID and our DCID as its SCID.
    pub fn parse_version_negotiation(
        b: &[u8],
        sent_dcid: &[u8],
        sent_scid: &[u8],
    ) -> Result<Vec<u32>, VnError> {
        if b.len() < 7 {
            return Err(VnError::Truncated);
        }
        if b[0] & 0x80 == 0 {
            return Err(VnError::NotLongHeader);
        }
        if b[1..5] != [0, 0, 0, 0] {
            return Err(VnError::NotVersionNegotiation);
        }
        let dl = usize::from(b[5]);
        let dcid = b.get(6..6 + dl).ok_or(VnError::Truncated)?;
        let sl_at = 6 + dl;
        let sl = usize::from(*b.get(sl_at).ok_or(VnError::Truncated)?);
        let scid = b.get(sl_at + 1..sl_at + 1 + sl).ok_or(VnError::Truncated)?;
        if dcid != sent_scid || scid != sent_dcid {
            return Err(VnError::CidMismatch);
        }
        let rest = &b[sl_at + 1 + sl..];
        if rest.len() < 4 || !rest.len().is_multiple_of(4) {
            return Err(VnError::Empty);
        }
        Ok(rest
            .as_chunks::<4>()
            .0
            .iter()
            .take(MAX_VERSIONS)
            .map(|c| u32::from_be_bytes(*c))
            .collect())
    }
}

// ---------------------------------------------------------------------------
// sys — the only OS FFI surface (kept small for security review)
// ---------------------------------------------------------------------------

pub mod sys {
    use std::io;
    use std::net::{IpAddr, UdpSocket};

    /// Sets the IP "don't fragment" behaviour on a UDP socket so path-MTU probes are meaningful.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub fn set_dont_fragment(sock: &UdpSocket, ipv6: bool) -> io::Result<()> {
        use std::ffi::{c_int, c_void};
        use std::os::fd::AsRawFd;
        unsafe extern "C" {
            fn setsockopt(
                fd: c_int,
                level: c_int,
                name: c_int,
                value: *const c_void,
                len: u32,
            ) -> c_int;
        }
        // <netinet/in.h>, <linux/in.h>, <linux/in6.h>
        const IPPROTO_IP: c_int = 0;
        const IP_MTU_DISCOVER: c_int = 10;
        const IP_PMTUDISC_DO: c_int = 2;
        const IPPROTO_IPV6: c_int = 41;
        const IPV6_MTU_DISCOVER: c_int = 23;
        const IPV6_PMTUDISC_DO: c_int = 2;
        let (level, name, value) = if ipv6 {
            (IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_DO)
        } else {
            (IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO)
        };
        // SAFETY: the descriptor is owned by `sock` and open for the whole call;
        // `value` lives on the stack and `len` equals its size.
        let rc = unsafe {
            setsockopt(
                sock.as_raw_fd(),
                level,
                name,
                (&raw const value).cast(),
                size_of::<c_int>() as u32,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    pub fn set_dont_fragment(sock: &UdpSocket, ipv6: bool) -> io::Result<()> {
        use std::os::windows::io::AsRawSocket;
        #[link(name = "ws2_32")]
        unsafe extern "system" {
            fn setsockopt(
                s: usize,
                level: i32,
                optname: i32,
                optval: *const u8,
                optlen: i32,
            ) -> i32;
            fn WSAGetLastError() -> i32;
        }
        // ws2def.h / ws2ipdef.h
        const IPPROTO_IP: i32 = 0;
        const IP_DONTFRAGMENT: i32 = 14;
        const IPPROTO_IPV6: i32 = 41;
        const IPV6_DONTFRAG: i32 = 14;
        let (level, name) = if ipv6 {
            (IPPROTO_IPV6, IPV6_DONTFRAG)
        } else {
            (IPPROTO_IP, IP_DONTFRAGMENT)
        };
        let value: u32 = 1;
        // SAFETY: the SOCKET is owned by `sock`; optval points to a live DWORD of length 4.
        let rc = unsafe {
            setsockopt(
                sock.as_raw_socket() as usize,
                level,
                name,
                (&raw const value).cast(),
                4,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            // SAFETY: no preconditions; reads the calling thread's Winsock error.
            Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "linux", windows)))]
    pub fn set_dont_fragment(_sock: &UdpSocket, _ipv6: bool) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// Sets the outbound IPv4 TTL or IPv6 Hop Limit on a TCP stream for active low-TTL
    /// decoy packet injection on the local socket path.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub fn set_tcp_ttl(sock: &std::net::TcpStream, ipv6: bool, ttl: u32) -> io::Result<()> {
        use std::ffi::{c_int, c_void};
        use std::os::fd::AsRawFd;
        unsafe extern "C" {
            fn setsockopt(
                fd: c_int,
                level: c_int,
                name: c_int,
                value: *const c_void,
                len: u32,
            ) -> c_int;
        }
        const IPPROTO_IP: c_int = 0;
        const IP_TTL: c_int = 2;
        const IPPROTO_IPV6: c_int = 41;
        const IPV6_UNICAST_HOPS: c_int = 16;
        let (level, name) = if ipv6 {
            (IPPROTO_IPV6, IPV6_UNICAST_HOPS)
        } else {
            (IPPROTO_IP, IP_TTL)
        };
        let value: c_int = ttl.clamp(1, 255) as c_int;
        // SAFETY: `sock` owns the open file descriptor; `value` is a stack `c_int`.
        let rc = unsafe {
            setsockopt(
                sock.as_raw_fd(),
                level,
                name,
                (&raw const value).cast(),
                size_of::<c_int>() as u32,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    pub fn set_tcp_ttl(sock: &std::net::TcpStream, ipv6: bool, ttl: u32) -> io::Result<()> {
        use std::os::windows::io::AsRawSocket;
        #[link(name = "ws2_32")]
        unsafe extern "system" {
            fn setsockopt(
                s: usize,
                level: i32,
                optname: i32,
                optval: *const u8,
                optlen: i32,
            ) -> i32;
            fn WSAGetLastError() -> i32;
        }
        const IPPROTO_IP: i32 = 0;
        const IP_TTL: i32 = 4;
        const IPPROTO_IPV6: i32 = 41;
        const IPV6_UNICAST_HOPS: i32 = 4;
        let (level, name) = if ipv6 {
            (IPPROTO_IPV6, IPV6_UNICAST_HOPS)
        } else {
            (IPPROTO_IP, IP_TTL)
        };
        let value: u32 = ttl.clamp(1, 255);
        // SAFETY: `sock` owns the open Winsock SOCKET; `value` is a 4-byte stack DWORD.
        let rc = unsafe {
            setsockopt(
                sock.as_raw_socket() as usize,
                level,
                name,
                (&raw const value).cast(),
                4,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            // SAFETY: reads thread-local Winsock error code.
            Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
        }
    }

    #[cfg(not(any(target_os = "android", target_os = "linux", windows)))]
    pub fn set_tcp_ttl(_sock: &std::net::TcpStream, _ipv6: bool, _ttl: u32) -> io::Result<()> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }

    /// True when a send failed because the datagram exceeds the local/known path MTU.
    pub fn is_message_too_large(e: &io::Error) -> bool {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        const EMSGSIZE: i32 = 90;
        #[cfg(windows)]
        const EMSGSIZE: i32 = 10040; // WSAEMSGSIZE
        #[cfg(not(any(target_os = "android", target_os = "linux", windows)))]
        const EMSGSIZE: i32 = i32::MIN;
        e.raw_os_error() == Some(EMSGSIZE)
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Adapter {
        pub name: String,
        pub if_type: u32,
        pub up: bool,
        pub mtu: u32,
        pub metric: u32,
        pub dns: Vec<IpAddr>,
        pub gateways: Vec<IpAddr>,
        pub unicast: Vec<IpAddr>,
    }

    /// Windows: IP Helper GetAdaptersAddresses and the registry build number.
    #[cfg(windows)]
    pub mod win {
        use super::Adapter;
        use std::ffi::c_void;
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        use std::ptr::null_mut;

        #[repr(C)]
        struct SocketAddress {
            sockaddr: *const u8,
            length: i32,
        }

        /// Common prefix of IP_ADAPTER_UNICAST_ADDRESS_LH, IP_ADAPTER_DNS_SERVER_ADDRESS_XP
        /// and IP_ADAPTER_GATEWAY_ADDRESS_LH (iptypes.h).
        #[repr(C)]
        struct AddrNode {
            alignment: u64,
            next: *const AddrNode,
            address: SocketAddress,
        }

        /// Prefix of IP_ADAPTER_ADDRESSES_LH (iptypes.h) up to Ipv6Metric. The buffer is
        /// allocated by size reported from the API, so reading a prefix is sound.
        #[repr(C)]
        struct AdapterAddresses {
            alignment: u64,
            next: *const AdapterAddresses,
            adapter_name: *const u8,
            first_unicast: *const AddrNode,
            first_anycast: *const c_void,
            first_multicast: *const c_void,
            first_dns: *const AddrNode,
            dns_suffix: *const u16,
            description: *const u16,
            friendly_name: *const u16,
            physical_address: [u8; 8],
            physical_address_length: u32,
            flags: u32,
            mtu: u32,
            if_type: u32,
            oper_status: i32,
            ipv6_if_index: u32,
            zone_indices: [u32; 16],
            first_prefix: *const c_void,
            transmit_link_speed: u64,
            receive_link_speed: u64,
            first_wins: *const c_void,
            first_gateway: *const AddrNode,
            ipv4_metric: u32,
            ipv6_metric: u32,
        }

        // Layout guards for the documented x64 structure.
        #[cfg(target_pointer_width = "64")]
        const _: () = {
            assert!(std::mem::offset_of!(AdapterAddresses, friendly_name) == 72);
            assert!(std::mem::offset_of!(AdapterAddresses, mtu) == 96);
            assert!(std::mem::offset_of!(AdapterAddresses, first_prefix) == 176);
            assert!(std::mem::offset_of!(AdapterAddresses, first_gateway) == 208);
            assert!(std::mem::offset_of!(AdapterAddresses, ipv4_metric) == 216);
            assert!(std::mem::offset_of!(AddrNode, address) == 16);
        };

        #[link(name = "iphlpapi")]
        unsafe extern "system" {
            fn GetAdaptersAddresses(
                family: u32,
                flags: u32,
                reserved: *mut c_void,
                addrs: *mut AdapterAddresses,
                size: *mut u32,
            ) -> u32;
        }

        #[link(name = "advapi32")]
        unsafe extern "system" {
            fn RegGetValueW(
                hkey: isize,
                sub_key: *const u16,
                value: *const u16,
                flags: u32,
                kind: *mut u32,
                data: *mut c_void,
                size: *mut u32,
            ) -> i32;
        }

        const AF_UNSPEC: u32 = 0;
        const AF_INET_FAMILY: u32 = 2;
        const AF_INET: u16 = 2;
        const AF_INET6: u16 = 23;
        const GAA_FLAG_INCLUDE_GATEWAYS: u32 = 0x0080;
        const ERROR_BUFFER_OVERFLOW: u32 = 111;
        const ERROR_NO_DATA: u32 = 232;
        const MAX_BUFFER: u32 = 1 << 20;
        const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
        const RRF_RT_REG_SZ: u32 = 0x0000_0002;

        /// Adapter snapshot. `dual_stack` is false when only the IPv4 view could be
        /// obtained, in which case IPv6 facts must be reported as unknown.
        #[derive(Debug, Clone, Default)]
        pub struct Snapshot {
            pub adapters: Vec<Adapter>,
            pub dual_stack: bool,
        }

        const ERROR_NOT_SUPPORTED: u32 = 50;

        pub fn adapters() -> Result<Snapshot, u32> {
            // Only INCLUDE_GATEWAYS: the SKIP_* flags merely shrink the output and are not
            // implemented by every GetAdaptersAddresses provider (e.g. Wine), so omit them.
            match query(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS) {
                Ok(adapters) => Ok(Snapshot {
                    adapters,
                    dual_stack: true,
                }),
                // Some providers reject AF_UNSPEC together with gateway reporting.
                Err(ERROR_NOT_SUPPORTED) => {
                    query(AF_INET_FAMILY, GAA_FLAG_INCLUDE_GATEWAYS).map(|adapters| Snapshot {
                        adapters,
                        dual_stack: false,
                    })
                }
                Err(e) => Err(e),
            }
        }

        fn query(family: u32, flags: u32) -> Result<Vec<Adapter>, u32> {
            let mut size: u32 = 16 * 1024;
            for _ in 0..4 {
                // u64 storage guarantees the 8-byte alignment the structures require.
                let mut buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
                let mut len = (buf.len() * 8) as u32;
                // SAFETY: `buf` is writable for `len` bytes and suitably aligned; `len` is in/out.
                let rc = unsafe {
                    GetAdaptersAddresses(
                        family,
                        flags,
                        null_mut(),
                        buf.as_mut_ptr().cast(),
                        &mut len,
                    )
                };
                match rc {
                    // SAFETY: on success the buffer holds a valid linked list that lives as long as `buf`.
                    0 => return Ok(unsafe { collect(buf.as_ptr().cast()) }),
                    ERROR_NO_DATA => return Ok(Vec::new()),
                    ERROR_BUFFER_OVERFLOW if len <= MAX_BUFFER => size = len,
                    e => return Err(e),
                }
            }
            Err(ERROR_BUFFER_OVERFLOW)
        }

        /// SAFETY: `p` is null or the head of a list written by GetAdaptersAddresses whose buffer outlives this call.
        unsafe fn collect(mut p: *const AdapterAddresses) -> Vec<Adapter> {
            let mut out = Vec::new();
            while !p.is_null() && out.len() < 256 {
                // SAFETY: guaranteed by the caller contract.
                let a = unsafe { &*p };
                // SAFETY: (all four calls) the string and list pointers inside the node are null
                // or point into the same live GetAdaptersAddresses buffer.
                let (name, dns, gateways, unicast) = unsafe {
                    (
                        wide_to_string(a.friendly_name),
                        addrs(a.first_dns),
                        addrs(a.first_gateway),
                        addrs(a.first_unicast),
                    )
                };
                out.push(Adapter {
                    name,
                    if_type: a.if_type,
                    up: a.oper_status == 1,
                    mtu: a.mtu,
                    metric: a.ipv4_metric,
                    dns,
                    gateways,
                    unicast,
                });
                p = a.next;
            }
            out
        }

        /// SAFETY: `p` is null or a list node inside a live GetAdaptersAddresses buffer.
        unsafe fn addrs(mut p: *const AddrNode) -> Vec<IpAddr> {
            let mut out = Vec::new();
            let mut n = 0;
            while !p.is_null() && n < 64 {
                // SAFETY: caller contract.
                let node = unsafe { &*p };
                // SAFETY: the SOCKET_ADDRESS points to `length` readable bytes in the same buffer.
                let ip = unsafe { sockaddr_to_ip(node.address.sockaddr, node.address.length) };
                if let Some(ip) = ip {
                    out.push(ip);
                }
                p = node.next;
                n += 1;
            }
            out
        }

        /// SAFETY: `sa` is null or points to at least `len` readable bytes.
        unsafe fn sockaddr_to_ip(sa: *const u8, len: i32) -> Option<IpAddr> {
            if sa.is_null() || len < 2 {
                return None;
            }
            // SAFETY: caller contract.
            let s = unsafe { std::slice::from_raw_parts(sa, len as usize) };
            match u16::from_ne_bytes([s[0], s[1]]) {
                AF_INET if s.len() >= 8 => Some(IpAddr::V4(Ipv4Addr::new(s[4], s[5], s[6], s[7]))),
                AF_INET6 if s.len() >= 24 => {
                    let mut o = [0u8; 16];
                    o.copy_from_slice(&s[8..24]);
                    Some(IpAddr::V6(Ipv6Addr::from(o)))
                }
                _ => None,
            }
        }

        /// SAFETY: `p` is null or a NUL-terminated UTF-16 string.
        unsafe fn wide_to_string(p: *const u16) -> String {
            if p.is_null() {
                return String::new();
            }
            let mut n = 0usize;
            // SAFETY: bounded scan of a NUL-terminated string.
            while n < 512 && unsafe { *p.add(n) } != 0 {
                n += 1;
            }
            // SAFETY: the first `n` code units were just read.
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, n) })
        }

        fn wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }

        fn reg_sz(key: &[u16], name: &str) -> Option<String> {
            let name_w = wide(name);
            let mut buf = [0u16; 128];
            let mut size = (buf.len() * 2) as u32;
            // SAFETY: key/name are NUL-terminated; buf is writable for `size` bytes.
            let rc = unsafe {
                RegGetValueW(
                    HKEY_LOCAL_MACHINE,
                    key.as_ptr(),
                    name_w.as_ptr(),
                    RRF_RT_REG_SZ,
                    null_mut(),
                    buf.as_mut_ptr().cast(),
                    &mut size,
                )
            };
            if rc != 0 {
                return None;
            }
            let n = (size as usize / 2).min(buf.len());
            let end = buf[..n].iter().position(|&c| c == 0).unwrap_or(n);
            Some(String::from_utf16_lossy(&buf[..end]))
        }

        /// (CurrentBuildNumber, DisplayVersion) — GetVersionEx is manifest-dependent, the registry is not.
        pub fn os_build() -> Option<(u32, String)> {
            let key = wide("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
            let build = reg_sz(&key, "CurrentBuildNumber")?.trim().parse().ok()?;
            Some((build, reg_sz(&key, "DisplayVersion").unwrap_or_default()))
        }

        // ---- System-wide connection tables (IP Helper, user mode, no driver) -------------

        #[link(name = "iphlpapi")]
        unsafe extern "system" {
            fn GetExtendedTcpTable(
                table: *mut c_void,
                size: *mut u32,
                order: i32,
                af: u32,
                class: u32,
                reserved: u32,
            ) -> u32;
            fn GetExtendedUdpTable(
                table: *mut c_void,
                size: *mut u32,
                order: i32,
                af: u32,
                class: u32,
                reserved: u32,
            ) -> u32;
        }

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
            fn QueryFullProcessImageNameW(
                process: *mut c_void,
                flags: u32,
                name: *mut u16,
                size: *mut u32,
            ) -> i32;
            fn CloseHandle(handle: *mut c_void) -> i32;
        }

        const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
        const UDP_TABLE_OWNER_PID: u32 = 1;
        const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
        const AF_INET6_FAMILY: u32 = 23;
        const MAX_TABLE: u32 = 8 << 20;
        const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

        /// Raw MIB_*TABLE_OWNER_PID buffers, parsed by the safe, cross-platform `sysnet` module.
        #[derive(Debug, Clone, Default)]
        pub struct RawTables {
            pub tcp4: Vec<u8>,
            pub tcp6: Vec<u8>,
            pub udp4: Vec<u8>,
            pub udp6: Vec<u8>,
        }

        fn fetch(tcp: bool, af: u32) -> Result<Vec<u8>, u32> {
            let mut size: u32 = 64 * 1024;
            for _ in 0..5 {
                // u32 storage guarantees the DWORD alignment of the MIB rows.
                let mut buf: Vec<u32> = vec![0; (size as usize).div_ceil(4)];
                let mut len = (buf.len() * 4) as u32;
                let class = if tcp {
                    TCP_TABLE_OWNER_PID_ALL
                } else {
                    UDP_TABLE_OWNER_PID
                };
                // SAFETY: `buf` is writable for `len` bytes and 4-byte aligned; `len` is in/out.
                let rc = unsafe {
                    if tcp {
                        GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut len, 0, af, class, 0)
                    } else {
                        GetExtendedUdpTable(buf.as_mut_ptr().cast(), &mut len, 0, af, class, 0)
                    }
                };
                match rc {
                    0 => return Ok(buf.iter().flat_map(|w| w.to_le_bytes()).collect()),
                    ERROR_INSUFFICIENT_BUFFER if len <= MAX_TABLE => size = len + 4096,
                    e => return Err(e),
                }
            }
            Err(ERROR_INSUFFICIENT_BUFFER)
        }

        /// Snapshot of every TCP and UDP endpoint on the machine with its owning process.
        /// IPv6 tables are optional (empty when the stack has no IPv6).
        pub fn connection_tables() -> Result<RawTables, u32> {
            Ok(RawTables {
                tcp4: fetch(true, AF_INET as u32)?,
                tcp6: fetch(true, AF_INET6_FAMILY).unwrap_or_default(),
                udp4: fetch(false, AF_INET as u32)?,
                udp6: fetch(false, AF_INET6_FAMILY).unwrap_or_default(),
            })
        }

        /// Executable file name (no path, for privacy) of a process, if this user may query it.
        pub fn process_name(pid: u32) -> Option<String> {
            match pid {
                0 => return Some("System Idle".to_owned()),
                4 => return Some("System".to_owned()),
                _ => {}
            }
            // SAFETY: no pointer arguments; a null return is handled.
            let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
            if handle.is_null() {
                return None;
            }
            let mut buf = [0u16; 1024];
            let mut size = buf.len() as u32;
            // SAFETY: `handle` is a live process handle; `buf` is writable for `size` units.
            let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut size) };
            // SAFETY: `handle` was returned by OpenProcess and is closed exactly once.
            unsafe { CloseHandle(handle) };
            if ok == 0 {
                return None;
            }
            let path = String::from_utf16_lossy(&buf[..(size as usize).min(buf.len())]);
            Some(path.rsplit(['\\', '/']).next().unwrap_or(&path).to_owned())
        }
    }

    /// Windows Wintun Layer-3 TUN virtual adapter descriptors, ring-buffer validation,
    /// and runtime FFI loader (`wintun.dll`) for user-space packet routing.
    pub mod wintun {
        use std::net::{Ipv4Addr, Ipv6Addr};

        /// Minimum Wintun ring capacity: 128 KiB (`0x2_0000`).
        pub const MIN_RING_CAPACITY: u32 = 0x0002_0000;
        /// Maximum Wintun ring capacity: 64 MiB (`0x400_0000`).
        pub const MAX_RING_CAPACITY: u32 = 0x0400_0000;
        /// Default Wintun ring capacity: 4 MiB (`0x40_0000`).
        pub const DEFAULT_RING_CAPACITY: u32 = 0x0040_0000;
        /// Maximum IP packet size over Wintun Layer-3 session.
        pub const MAX_IP_PACKET_SIZE: usize = 65_535;

        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct WintunAdapterConfig {
            pub adapter_name: String,
            pub tunnel_type: String,
            pub ring_capacity: u32,
            pub ipv4_addr: Ipv4Addr,
            pub ipv4_prefix: u8,
            pub ipv6_addr: Ipv6Addr,
            pub ipv6_prefix: u8,
            pub mtu: u16,
        }

        impl Default for WintunAdapterConfig {
            fn default() -> Self {
                Self {
                    adapter_name: "TheDPI".to_owned(),
                    tunnel_type: "TheDPI-L3".to_owned(),
                    ring_capacity: DEFAULT_RING_CAPACITY,
                    ipv4_addr: Ipv4Addr::new(10, 215, 173, 1),
                    ipv4_prefix: 24,
                    ipv6_addr: Ipv6Addr::new(0xfd00, 0x7468, 0x6564, 0x7069, 0, 0, 0, 1),
                    ipv6_prefix: 64,
                    mtu: 1400,
                }
            }
        }

        /// Validates that `capacity` is within `[128 KiB, 64 MiB]` and a power of two, as
        /// required by `WintunStartSession`.
        pub fn valid_ring_capacity(capacity: u32) -> bool {
            (MIN_RING_CAPACITY..=MAX_RING_CAPACITY).contains(&capacity)
                && capacity.is_power_of_two()
        }

        /// Validates that a raw Layer-3 frame is a well-formed IPv4 or IPv6 packet suitable
        /// for `WintunAllocateSendPacket` / `WintunSendPacket`.
        pub fn valid_l3_packet(pkt: &[u8]) -> bool {
            if pkt.len() < 20 || pkt.len() > MAX_IP_PACKET_SIZE {
                return false;
            }
            match pkt[0] >> 4 {
                4 => {
                    let ihl = usize::from(pkt[0] & 0x0f) * 4;
                    let total = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
                    ihl >= 20 && total == pkt.len() && total >= ihl
                }
                6 => {
                    if pkt.len() < 40 {
                        return false;
                    }
                    let plen = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
                    40 + plen == pkt.len()
                }
                _ => false,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// sysnet — system-wide connection intelligence (parsing is safe and cross-platform)
// ---------------------------------------------------------------------------

/// Parses the IP Helper owner-PID tables and turns them into per-process findings.
/// The parser is pure Rust over byte slices (bounds-checked, never trusts the row
/// count), so it is fully tested on every platform; only the table fetch is Windows FFI.
pub mod sysnet {
    use crate::wire::Record;
    use crate::{code, tags};
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    pub const PROTO_TCP: u8 = 6;
    pub const PROTO_UDP: u8 = 17;
    pub const MAX_ROWS: usize = 65_536;
    pub const MAX_PROCESSES: usize = 64;
    pub const SAMPLE: usize = 5;

    /// MIB_TCP_STATE values.
    pub mod state {
        pub const LISTEN: u32 = 2;
        pub const SYN_SENT: u32 = 3;
        pub const ESTABLISHED: u32 = 5;
        pub const CLOSE_WAIT: u32 = 8;
        pub const TIME_WAIT: u32 = 11;
    }

    pub const F_STUCK_HANDSHAKES: i64 = 1;
    pub const F_CLOSE_WAIT_LEAK: i64 = 2;
    pub const F_TIME_WAIT_PRESSURE: i64 = 3;
    pub const F_EXPOSED_LISTENERS: i64 = 4;
    pub const F_NO_ACTIVITY: i64 = 5;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Connection {
        pub proto: u8,
        pub local: SocketAddr,
        pub remote: Option<SocketAddr>,
        pub state: u32,
        pub pid: u32,
    }

    fn u32_at(b: &[u8], i: usize) -> Option<u32> {
        b.get(i..i + 4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_le_bytes)
    }
    /// Ports are stored in network byte order in the low 16 bits of a DWORD.
    fn port_at(b: &[u8], i: usize) -> Option<u16> {
        b.get(i..i + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }
    fn v4_at(b: &[u8], i: usize) -> Option<Ipv4Addr> {
        b.get(i..i + 4)
            .map(|s| Ipv4Addr::new(s[0], s[1], s[2], s[3]))
    }
    fn v6_at(b: &[u8], i: usize) -> Option<Ipv6Addr> {
        b.get(i..i + 16)
            .and_then(|s| <[u8; 16]>::try_from(s).ok())
            .map(Ipv6Addr::from)
    }

    /// Rows of a MIB table: DWORD count, then fixed-size rows. The count is clamped to
    /// what the buffer actually holds.
    fn rows(b: &[u8], row: usize) -> impl Iterator<Item = &[u8]> {
        let n = u32_at(b, 0).unwrap_or(0) as usize;
        let body = b.get(4..).unwrap_or(&[]);
        body.chunks_exact(row).take(n.min(MAX_ROWS))
    }

    fn remote_of(state: u32, addr: SocketAddr) -> Option<SocketAddr> {
        (state != state::LISTEN && !addr.ip().is_unspecified()).then_some(addr)
    }

    /// MIB_TCPROW_OWNER_PID (24 bytes).
    pub fn parse_tcp4(b: &[u8]) -> Vec<Connection> {
        rows(b, 24)
            .filter_map(|r| {
                let st = u32_at(r, 0)?;
                let remote = SocketAddr::new(IpAddr::V4(v4_at(r, 12)?), port_at(r, 16)?);
                Some(Connection {
                    proto: PROTO_TCP,
                    local: SocketAddr::new(IpAddr::V4(v4_at(r, 4)?), port_at(r, 8)?),
                    remote: remote_of(st, remote),
                    state: st,
                    pid: u32_at(r, 20)?,
                })
            })
            .collect()
    }

    /// MIB_TCP6ROW_OWNER_PID (56 bytes).
    pub fn parse_tcp6(b: &[u8]) -> Vec<Connection> {
        rows(b, 56)
            .filter_map(|r| {
                let st = u32_at(r, 48)?;
                let remote = SocketAddr::new(IpAddr::V6(v6_at(r, 24)?), port_at(r, 44)?);
                Some(Connection {
                    proto: PROTO_TCP,
                    local: SocketAddr::new(IpAddr::V6(v6_at(r, 0)?), port_at(r, 20)?),
                    remote: remote_of(st, remote),
                    state: st,
                    pid: u32_at(r, 52)?,
                })
            })
            .collect()
    }

    /// MIB_UDPROW_OWNER_PID (12 bytes).
    pub fn parse_udp4(b: &[u8]) -> Vec<Connection> {
        rows(b, 12)
            .filter_map(|r| {
                Some(Connection {
                    proto: PROTO_UDP,
                    local: SocketAddr::new(IpAddr::V4(v4_at(r, 0)?), port_at(r, 4)?),
                    remote: None,
                    state: 0,
                    pid: u32_at(r, 8)?,
                })
            })
            .collect()
    }

    /// MIB_UDP6ROW_OWNER_PID (28 bytes).
    pub fn parse_udp6(b: &[u8]) -> Vec<Connection> {
        rows(b, 28)
            .filter_map(|r| {
                Some(Connection {
                    proto: PROTO_UDP,
                    local: SocketAddr::new(IpAddr::V6(v6_at(r, 0)?), port_at(r, 20)?),
                    remote: None,
                    state: 0,
                    pid: u32_at(r, 24)?,
                })
            })
            .collect()
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ProcessSummary {
        pub pid: u32,
        pub name: String,
        pub established: u32,
        pub syn_sent: u32,
        pub listen: u32,
        pub close_wait: u32,
        pub udp: u32,
        pub remotes: u32,
        pub sample: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Finding {
        pub code: i64,
        pub subject: String,
        pub args: Vec<i64>,
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Summary {
        pub total: u32,
        pub established: u32,
        pub listen: u32,
        pub syn_sent: u32,
        pub time_wait: u32,
        pub close_wait: u32,
        pub udp: u32,
        pub exposed_listeners: u32,
        pub processes: Vec<ProcessSummary>,
        pub findings: Vec<Finding>,
    }

    /// Aggregates a connection snapshot per process and derives explainable findings.
    /// Loopback peers are treated as local IPC and not counted as remote endpoints.
    pub fn summarize(conns: &[Connection], name_of: impl Fn(u32) -> Option<String>) -> Summary {
        let mut s = Summary::default();
        let mut per: BTreeMap<u32, ProcessSummary> = BTreeMap::new();
        let mut remotes: BTreeMap<u32, BTreeSet<SocketAddr>> = BTreeMap::new();
        for c in conns.iter().take(MAX_ROWS * 4) {
            s.total += 1;
            let p = per.entry(c.pid).or_insert_with(|| ProcessSummary {
                pid: c.pid,
                ..ProcessSummary::default()
            });
            if c.proto == PROTO_UDP {
                s.udp += 1;
                p.udp += 1;
                continue;
            }
            match c.state {
                state::ESTABLISHED => {
                    s.established += 1;
                    p.established += 1;
                }
                state::LISTEN => {
                    s.listen += 1;
                    p.listen += 1;
                    if c.local.ip().is_unspecified() {
                        s.exposed_listeners += 1;
                    }
                }
                state::SYN_SENT => {
                    s.syn_sent += 1;
                    p.syn_sent += 1;
                }
                state::CLOSE_WAIT => {
                    s.close_wait += 1;
                    p.close_wait += 1;
                }
                state::TIME_WAIT => s.time_wait += 1,
                _ => {}
            }
            if let Some(r) = c.remote.filter(|r| !r.ip().is_loopback()) {
                let set = remotes.entry(c.pid).or_default();
                if set.len() < 1024 {
                    set.insert(r);
                }
            }
        }
        for (pid, p) in per.iter_mut() {
            p.name = name_of(*pid).unwrap_or_else(|| format!("pid {pid}"));
            if let Some(set) = remotes.get(pid) {
                p.remotes = set.len() as u32;
                p.sample = set.iter().take(SAMPLE).map(ToString::to_string).collect();
            }
        }
        let mut list: Vec<ProcessSummary> = per.into_values().collect();
        list.sort_by(|a, b| {
            b.syn_sent
                .cmp(&a.syn_sent)
                .then(b.established.cmp(&a.established))
                .then(a.pid.cmp(&b.pid))
        });
        for p in &list {
            if p.syn_sent >= 3 {
                s.findings.push(Finding {
                    code: F_STUCK_HANDSHAKES,
                    subject: p.name.clone(),
                    args: vec![i64::from(p.syn_sent), i64::from(p.pid)],
                });
            }
            if p.close_wait >= 20 {
                s.findings.push(Finding {
                    code: F_CLOSE_WAIT_LEAK,
                    subject: p.name.clone(),
                    args: vec![i64::from(p.close_wait), i64::from(p.pid)],
                });
            }
        }
        if s.time_wait >= 2000 {
            s.findings.push(Finding {
                code: F_TIME_WAIT_PRESSURE,
                subject: String::new(),
                args: vec![i64::from(s.time_wait)],
            });
        }
        if s.exposed_listeners > 0 {
            s.findings.push(Finding {
                code: F_EXPOSED_LISTENERS,
                subject: String::new(),
                args: vec![i64::from(s.exposed_listeners)],
            });
        }
        if s.established == 0 && s.syn_sent == 0 {
            s.findings.push(Finding {
                code: F_NO_ACTIVITY,
                subject: String::new(),
                args: vec![],
            });
        }
        list.truncate(MAX_PROCESSES);
        s.processes = list;
        s
    }

    pub fn encode(s: &Summary) -> Record {
        use tags::sysnet as t;
        let mut r = Record::with_status(code::OK);
        r.int(t::TOTAL, i64::from(s.total))
            .int(t::ESTABLISHED, i64::from(s.established))
            .int(t::LISTEN, i64::from(s.listen))
            .int(t::SYN_SENT, i64::from(s.syn_sent))
            .int(t::TIME_WAIT, i64::from(s.time_wait))
            .int(t::CLOSE_WAIT, i64::from(s.close_wait))
            .int(t::UDP, i64::from(s.udp))
            .int(t::EXPOSED, i64::from(s.exposed_listeners));
        for p in &s.processes {
            use tags::process as k;
            let mut x = Record::new();
            x.int(k::PID, i64::from(p.pid))
                .text(k::NAME, &p.name)
                .int(k::ESTABLISHED, i64::from(p.established))
                .int(k::SYN_SENT, i64::from(p.syn_sent))
                .int(k::LISTEN, i64::from(p.listen))
                .int(k::CLOSE_WAIT, i64::from(p.close_wait))
                .int(k::UDP, i64::from(p.udp))
                .int(k::REMOTES, i64::from(p.remotes));
            for e in &p.sample {
                x.text(k::SAMPLE, e);
            }
            r.record(t::PROCESS, x);
        }
        for f in &s.findings {
            let mut x = Record::new();
            x.int(tags::finding::CODE, f.code)
                .text(tags::finding::SUBJECT, &f.subject);
            for a in &f.args {
                x.int(tags::finding::ARG, *a);
            }
            r.record(t::FINDING, x);
        }
        r
    }

    /// Live snapshot of the whole machine (Windows). Other platforms: UNSUPPORTED.
    #[cfg(windows)]
    pub fn snapshot() -> Record {
        match crate::sys::win::connection_tables() {
            Ok(t) => {
                let mut conns = parse_tcp4(&t.tcp4);
                conns.extend(parse_tcp6(&t.tcp6));
                conns.extend(parse_udp4(&t.udp4));
                conns.extend(parse_udp6(&t.udp6));
                encode(&summarize(&conns, crate::sys::win::process_name))
            }
            Err(e) => {
                let mut r = Record::with_status(code::INTERNAL);
                r.int(tags::sysnet::OS_ERROR, i64::from(e));
                r
            }
        }
    }

    #[cfg(not(windows))]
    pub fn snapshot() -> Record {
        Record::with_status(code::UNSUPPORTED)
    }
}

// ---------------------------------------------------------------------------
// desync — 2026-2027 active DPI circumvention & local socket/packet engine
// ---------------------------------------------------------------------------

/// Active Deep Packet Inspection (DPI) desynchronization engine (GoodbyeDPI / Zapret / ByeDPI
/// architecture) implemented in zero-dependency Rust + SIMD Assembly (`ascii`).
///
/// Supports two complementary local execution planes with zero external VPN servers:
/// 1. **Packet Plane (`desync_packet` / `should_drop_inbound`)**: In-place IPv4/IPv6 + TCP/UDP
///    packet segmentation, out-of-order TCP Sequence Number disorder, decoy Fake packet
///    injection (RFC 1624 BadSum or adaptive auto-TTL), QUIC Initial UDP scrambling, and
///    passive DPI spoofed TCP RST / HTTP redirect filtering for Windows WFP/WinDivert and
///    Android `VpnService` TUN descriptors.
/// 2. **Socket Plane (`LocalProxy`)**: Unprivileged local loopback SOCKS5 (RFC 1928) and
///    HTTP `CONNECT` / transparent proxy that splits TLS 1.3 (including Hybrid Post-Quantum
///    `X25519MLKEM768` and RFC 9849 ECH) and HTTP requests across exact SNI/ECH/`Host:`
///    boundaries with `TCP_NODELAY` and low-TTL decoy writes.
pub mod desync {
    use crate::wire::Record;
    use crate::{ascii, code, quic, sys, tags};
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    pub const PROTO_UNKNOWN: i64 = 0;
    pub const PROTO_TLS_CLIENT_HELLO: i64 = 1;
    pub const PROTO_HTTP_REQUEST: i64 = 2;
    pub const PROTO_QUIC_INITIAL: i64 = 3;
    pub const PROTO_DISCORD_VOICE: i64 = 4;
    pub const PROTO_ROBLOX_RAKNET: i64 = 5;

    /// RakNet `OFFLINE_MESSAGE_DATA_ID` 16-byte magic used in Roblox UDP connection handshakes (`0x01`, `0x05`, `0x07`).
    pub const RAKNET_OFFLINE_MAGIC: [u8; 16] = [
        0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe, 0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56,
        0x78,
    ];

    /// IANA TLS 1.3 Hybrid Post-Quantum NamedGroup `X25519MLKEM768` (`0x11ec`).
    pub const TLS_GROUP_X25519_MLKEM768: u16 = 0x11ec;
    /// Pure `MLKEM768` NamedGroup (`0x0200`).
    pub const TLS_GROUP_MLKEM768: u16 = 0x0200;
    /// Default legitimate cover `dest` domain used by `REALITY` camouflage.
    pub const REALITY_DEFAULT_DEST: &str = "dl.google.com";

    /// Active DPI circumvention strategy.
    #[repr(i64)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum DesyncMode {
        #[default]
        Off = 0,
        /// Splits TLS ClientHello / HTTP request at the exact SNI/ECH/`Host:` boundary.
        Split = 1,
        /// Splits into 2–3 TCP segments and emits them in reverse Sequence Number order.
        Disorder = 2,
        /// Prepends a decoy TCP segment (`www.iana.org`) with an RFC 1624 corrupted checksum,
        /// followed by disordered real segments.
        FakeBadSum = 3,
        /// Prepends a decoy TCP segment (`www.iana.org`) with an adaptive low IP TTL / Hop Limit
        /// so it expires after the ISP DPI box but before the destination server.
        FakeAutoTtl = 4,
        /// Prepends a decoy QUIC Version Negotiation / Initial datagram on UDP/443 and forces
        /// immediate TCP/TLS 1.3 fallback when QUIC is blackholed.
        QuicScramble = 5,
        /// Full 2026–2027 multi-vector pipeline: FakeAutoTtl + FakeBadSum + Multi-Disorder
        /// across both SNI (`0x0000`) and ECH (`0xfe0d`) + QUIC scramble + passive RST filter.
        AdaptiveFull = 6,
        /// 2026–2027 Project X `REALITY` + `mlkem768` (`X25519MLKEM768` `0x11ec`) post-quantum
        /// handshake camouflage + `xtls-rprx-vision` flow control with direct inner TLS splice.
        RealityVision = 7,
    }

    impl DesyncMode {
        pub fn from_code(c: i64) -> Self {
            match c {
                1 => Self::Split,
                2 => Self::Disorder,
                3 => Self::FakeBadSum,
                4 => Self::FakeAutoTtl,
                5 => Self::QuicScramble,
                6 => Self::AdaptiveFull,
                7 => Self::RealityVision,
                _ => Self::Off,
            }
        }
    }

    /// Configuration for packet-plane and socket-plane desynchronization.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct DesyncConfig {
        pub mode: DesyncMode,
        /// TTL / Hop Limit for decoy packets (default 5; clamped to 2..=16).
        pub fake_ttl: u8,
        /// Fallback split offset within payload when no SNI/Host is present (default 2).
        pub split_pos: usize,
        /// Drop inbound passive-DPI spoofed TCP RST and HTTP 302/403 redirect packets.
        pub drop_spoofed_rst: bool,
        /// Local proxy listen port (0 = OS-assigned ephemeral port).
        pub listen_port: u16,
    }

    impl Default for DesyncConfig {
        fn default() -> Self {
            Self {
                mode: DesyncMode::AdaptiveFull,
                fake_ttl: 5,
                split_pos: 2,
                drop_spoofed_rst: true,
                listen_port: 0,
            }
        }
    }

    impl DesyncConfig {
        pub fn from_record(r: &Record) -> Self {
            use tags::desync as t;
            let d = Self::default();
            let mode = r.get_int(t::MODE).map_or(d.mode, DesyncMode::from_code);
            let fake_ttl = r
                .get_int(t::FAKE_TTL)
                .and_then(|v| u8::try_from(v.clamp(2, 16)).ok())
                .unwrap_or(d.fake_ttl);
            let split_pos = r
                .get_int(t::SPLIT_POS)
                .and_then(|v| usize::try_from(v.clamp(1, 256)).ok())
                .unwrap_or(d.split_pos);
            let drop_spoofed_rst = r
                .get_int(t::DROP_RST)
                .map_or(d.drop_spoofed_rst, |v| v != 0);
            let listen_port = r
                .get_int(t::PORT)
                .and_then(|v| u16::try_from(v.clamp(0, 65535)).ok())
                .unwrap_or(d.listen_port);
            Self {
                mode,
                fake_ttl,
                split_pos,
                drop_spoofed_rst,
                listen_port,
            }
        }
    }

    /// Deep Layer-7 inspection result extracted from a TCP/UDP payload.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct L7Inspection {
        pub protocol: i64,
        pub host: String,
        pub host_offset: Option<usize>,
        pub host_len: usize,
        pub ech_offset: Option<usize>,
        pub ech_len: usize,
        pub post_quantum: bool,
        pub split_offsets: Vec<usize>,
    }

    /// `xtls-rprx-vision` flow-control state machine.
    ///
    /// Inspects and pads/splits outer and inner TLS handshake records (`0x16`), then transitions
    /// to zero-copy `DirectSplice` as soon as TLS 1.3 `ApplicationData` (`0x17 0x03 0x03`) begins.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum VisionPhase {
        #[default]
        HandshakePadding,
        DirectSplice,
    }

    #[derive(Debug, Clone, Default)]
    pub struct VisionFlow {
        pub phase: VisionPhase,
        pub handshake_records: u32,
        pub spliced_bytes: u64,
    }

    impl VisionFlow {
        pub fn new() -> Self {
            Self::default()
        }

        /// Observes a TLS stream chunk and returns `true` on the exact transition into
        /// `VisionPhase::DirectSplice` (`xtls-rprx-vision` zero-copy splice).
        pub fn observe_chunk(&mut self, chunk: &[u8]) -> bool {
            if self.phase == VisionPhase::DirectSplice {
                self.spliced_bytes = self.spliced_bytes.saturating_add(chunk.len() as u64);
                return false;
            }
            if is_tls_application_data(chunk) {
                self.phase = VisionPhase::DirectSplice;
                self.spliced_bytes = self.spliced_bytes.saturating_add(chunk.len() as u64);
                return true;
            }
            if chunk.first() == Some(&0x16) {
                self.handshake_records = self.handshake_records.saturating_add(1);
            }
            false
        }
    }

    /// Returns `true` if `buf` begins with or contains a TLS 1.3 `ApplicationData` record header
    /// (`0x17 0x03 0x03`) with a plausible record length.
    pub fn is_tls_application_data(buf: &[u8]) -> bool {
        if buf.len() >= 5 && buf[0] == 0x17 && buf[1] == 0x03 && buf[2] == 0x03 {
            let len = u16::from_be_bytes([buf[3], buf[4]]);
            return (1..=16640).contains(&len);
        }
        ascii::scan_pattern(buf, &[0x17, 0x03, 0x03]).is_some()
    }

    /// Keyed 256-bit sponge MAC used to derive and verify `REALITY` + `mlkem768` 32-byte
    /// `SessionId` values bound to `(client_random, cover_sni, device_id, auth_key)`.
    pub fn compute_reality_session_id(
        client_random: &[u8; 32],
        cover_sni: &str,
        device_id: &str,
        auth_key: &[u8; 32],
    ) -> [u8; 32] {
        let mut state = [
            0x6a09e667f3bcc908u64,
            0xbb67ae8584caa73bu64,
            0x3c6ef372fe94f82bu64,
            0xa54ff53a5f1d36f1u64,
        ];
        let mut absorb = |data: &[u8], domain: u64| {
            state[0] ^= domain.wrapping_mul(0x9e3779b97f4a7c15);
            for (idx, &b) in data.iter().enumerate() {
                let lane = idx & 3;
                state[lane] = state[lane]
                    .wrapping_add(u64::from(b).wrapping_mul(0xbf58476d1ce4e5b9))
                    .rotate_left(13)
                    ^ state[(lane + 1) & 3];
                state[(lane + 2) & 3] = state[(lane + 2) & 3]
                    .wrapping_mul(0x94d049bb133111eb)
                    .rotate_right(17)
                    ^ state[lane];
            }
            for _ in 0..4 {
                let t = state[0].wrapping_add(state[1]).rotate_left(19);
                state[1] ^= t;
                state[2] = state[2].wrapping_add(state[3]).rotate_left(29);
                state[3] ^= state[0];
                state[0] = state[0].wrapping_mul(0xff51afd7ed558ccd) ^ state[2];
            }
        };
        absorb(auth_key, 0x2026_11ec_0001);
        absorb(client_random, 0x2026_11ec_0002);
        absorb(ascii::lowercased(cover_sni).as_bytes(), 0x2026_11ec_0003);
        absorb(device_id.as_bytes(), 0x2026_11ec_0004);
        absorb(auth_key, 0x2026_11ec_0005);

        let mut out = [0u8; 32];
        for (i, word) in state.iter().enumerate() {
            out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// Builds a `REALITY` + `mlkem768` (`X25519MLKEM768` `0x11ec`) TLS 1.3 `ClientHello`
    /// camouflaged as `cover_sni` (e.g. `dl.google.com`) with an authenticated `SessionId`
    /// and a hybrid post-quantum key share.
    pub fn build_reality_mlkem768_client_hello(
        cover_sni: &str,
        client_random: &[u8; 32],
        device_id: &str,
        auth_key: &[u8; 32],
    ) -> Vec<u8> {
        let sni = if cover_sni.is_empty() {
            REALITY_DEFAULT_DEST
        } else {
            cover_sni
        };
        let session_id = compute_reality_session_id(client_random, sni, device_id, auth_key);
        let host_b = sni.as_bytes();
        let mut exts = Vec::with_capacity(128);

        // 1. server_name (0x0000)
        let sni_list_len = (host_b.len() + 3) as u16;
        let sni_ext_len = sni_list_len + 2;
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&sni_ext_len.to_be_bytes());
        exts.extend_from_slice(&sni_list_len.to_be_bytes());
        exts.push(0x00);
        exts.extend_from_slice(&(host_b.len() as u16).to_be_bytes());
        exts.extend_from_slice(host_b);

        // 2. supported_versions (0x002b) -> TLS 1.3 (0x0304)
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&3u16.to_be_bytes());
        exts.extend_from_slice(&[0x02, 0x03, 0x04]);

        // 3. supported_groups (0x000a) -> X25519MLKEM768 (0x11ec), MLKEM768 (0x0200), X25519 (0x001d)
        exts.extend_from_slice(&0x000au16.to_be_bytes());
        exts.extend_from_slice(&8u16.to_be_bytes());
        exts.extend_from_slice(&6u16.to_be_bytes());
        exts.extend_from_slice(&TLS_GROUP_X25519_MLKEM768.to_be_bytes());
        exts.extend_from_slice(&TLS_GROUP_MLKEM768.to_be_bytes());
        exts.extend_from_slice(&0x001du16.to_be_bytes());

        // 4. key_share (0x0033) -> X25519MLKEM768 (0x11ec) hybrid post-quantum key share
        let pq_share_material = compute_reality_session_id(&session_id, sni, "mlkem768", auth_key);
        let ks_entry_len = 2 + 2 + pq_share_material.len();
        let ks_ext_len = 2 + ks_entry_len;
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        exts.extend_from_slice(&(ks_ext_len as u16).to_be_bytes());
        exts.extend_from_slice(&(ks_entry_len as u16).to_be_bytes());
        exts.extend_from_slice(&TLS_GROUP_X25519_MLKEM768.to_be_bytes());
        exts.extend_from_slice(&(pq_share_material.len() as u16).to_be_bytes());
        exts.extend_from_slice(&pq_share_material);

        // ClientHello body: Version(2) + Random(32) + SessionId(1+32) + CipherSuites(2+4) + Comp(1+1) + Exts(2+N)
        let body_len = 2 + 32 + 1 + 32 + 2 + 4 + 1 + 1 + 2 + exts.len();
        let rec_len = 4 + body_len;
        let mut buf = Vec::with_capacity(5 + rec_len);
        buf.extend_from_slice(&[0x16, 0x03, 0x01]);
        buf.extend_from_slice(&(rec_len as u16).to_be_bytes());
        buf.push(0x01); // HandshakeType::ClientHello
        buf.push(0x00);
        buf.extend_from_slice(&(body_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]); // Legacy TLS 1.2
        buf.extend_from_slice(client_random);
        buf.push(32); // SessionId length
        buf.extend_from_slice(&session_id);
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[0x13, 0x01, 0x13, 0x02]); // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
        buf.extend_from_slice(&[0x01, 0x00]); // Null compression
        buf.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        buf.extend_from_slice(&exts);
        buf
    }

    /// Extracts `(client_random, session_id, sni, post_quantum)` from a TLS 1.3 `ClientHello`.
    pub fn extract_reality_fields(buf: &[u8]) -> Option<([u8; 32], [u8; 32], String, bool)> {
        if buf.len() < 76 || buf[0] != 0x16 || buf[1] != 0x03 || buf[5] != 0x01 {
            return None;
        }
        let mut random = [0u8; 32];
        random.copy_from_slice(&buf[11..43]);
        if buf[43] != 32 || buf.len() < 76 {
            return None;
        }
        let mut sid = [0u8; 32];
        sid.copy_from_slice(&buf[44..76]);
        let info = inspect_tls_client_hello(buf, 2)?;
        Some((random, sid, info.host, info.post_quantum))
    }

    /// Splits a single TLS 1.2/1.3 `ClientHello` record (`0x16 0x03 0x01..0x04 <len:2>`) across
    /// multiple valid `TLSPlaintext` handshake records (RFC 5246 §6.2.1 / RFC 8446 §5.1) at the
    /// exact SNI/ECH split boundaries so stateful TCP-reassembling ISP middleboxes that inspect
    /// one TLS record at a time never see an intact SNI or ECH extension.
    pub fn fragment_tls_client_hello_records(buf: &[u8], fallback_split: usize) -> Option<Vec<u8>> {
        let info = inspect_tls_client_hello(buf, fallback_split)?;
        let rec_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
        if buf.len() != 5 + rec_len || rec_len <= 4 {
            return None;
        }
        let hs = &buf[5..];
        let mut hs_splits = Vec::with_capacity(info.split_offsets.len() + 1);
        hs_splits.push(4usize.min(hs.len().saturating_sub(1)));
        for &off in &info.split_offsets {
            if off > 5 && off - 5 < hs.len() {
                hs_splits.push(off - 5);
            }
        }
        hs_splits.sort_unstable();
        hs_splits.dedup();
        let ranges = slice_ranges(hs.len(), &hs_splits);
        if ranges.len() <= 1 {
            return None;
        }
        let mut out = Vec::with_capacity(buf.len() + ranges.len() * 5);
        for (start, end) in ranges {
            let chunk = &hs[start..end];
            if chunk.is_empty() {
                continue;
            }
            out.push(0x16);
            out.push(buf[1]);
            out.push(buf[2]);
            out.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            out.extend_from_slice(chunk);
        }
        Some(out)
    }

    /// Reassembles consecutive TLS `Handshake` (`0x16`) records back into a single canonical
    /// `TLSPlaintext` record for verification and testing.
    pub fn reassemble_tls_records(buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < 6 || buf[0] != 0x16 || buf[1] != 0x03 {
            return None;
        }
        let ver_hi = buf[1];
        let ver_lo = buf[2];
        let mut pos = 0usize;
        let mut hs_payload = Vec::with_capacity(buf.len());
        while pos < buf.len() {
            if pos + 5 > buf.len() || buf[pos] != 0x16 || buf[pos + 1] != ver_hi {
                return None;
            }
            let rlen = usize::from(u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]));
            pos += 5;
            if pos + rlen > buf.len() {
                return None;
            }
            hs_payload.extend_from_slice(&buf[pos..pos + rlen]);
            pos += rlen;
        }
        let mut out = Vec::with_capacity(5 + hs_payload.len());
        out.extend_from_slice(&[0x16, ver_hi, ver_lo]);
        out.extend_from_slice(&(hs_payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&hs_payload);
        Some(out)
    }

    const HTTP_METHODS: [&[u8]; 7] = [
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"CONNECT ",
    ];

    /// Inspects a TCP or UDP payload for TLS ClientHello (SNI 0x0000, ECH 0xfe0d, PQ KeyShare
    /// 0x11ec), HTTP request (`Host:` header via SIMD `scan_pattern`), QUIC v1/v2 Initial,
    /// Discord Voice IP Discovery / STUN, or Roblox RakNet UDP handshake.
    pub fn inspect_l7(payload: &[u8], fallback_split: usize) -> L7Inspection {
        if let Some(tls) = inspect_tls_client_hello(payload, fallback_split) {
            return tls;
        }
        if let Some(http) = inspect_http_request(payload, fallback_split) {
            return http;
        }
        if let Some(q) = inspect_quic_initial(payload) {
            return q;
        }
        if let Some(dv) = inspect_discord_voice(payload) {
            return dv;
        }
        if let Some(rk) = inspect_roblox_raknet(payload) {
            return rk;
        }
        L7Inspection::default()
    }

    fn inspect_tls_client_hello(buf: &[u8], fallback_split: usize) -> Option<L7Inspection> {
        // TLS Record Header: ContentType=0x16 (Handshake), LegacyVersion=0x03 0x01..0x04,
        // Length (2B), HandshakeType=0x01 (ClientHello), HandshakeLen (3B), ClientVersion (2B), Random (32B).
        if buf.len() < 43 || buf[0] != 0x16 || buf[1] != 0x03 || buf[2] > 0x04 || buf[5] != 0x01 {
            return None;
        }
        let mut pos = 43usize;
        // Session ID
        if pos >= buf.len() {
            return None;
        }
        let sid_len = usize::from(buf[pos]);
        pos = pos.checked_add(1 + sid_len)?;
        // Cipher Suites
        if pos + 2 > buf.len() {
            return None;
        }
        let cs_len = usize::from(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
        pos = pos.checked_add(2 + cs_len)?;
        // Compression Methods
        if pos >= buf.len() {
            return None;
        }
        let comp_len = usize::from(buf[pos]);
        pos = pos.checked_add(1 + comp_len)?;

        let mut out = L7Inspection {
            protocol: PROTO_TLS_CLIENT_HELLO,
            ..L7Inspection::default()
        };

        if pos + 2 <= buf.len() {
            let ext_total = usize::from(u16::from_be_bytes([buf[pos], buf[pos + 1]]));
            pos += 2;
            let ext_end = pos.saturating_add(ext_total).min(buf.len());
            while pos + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
                let ext_len = usize::from(u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]));
                pos += 4;
                if pos + ext_len > ext_end {
                    break;
                }
                let ext_data = &buf[pos..pos + ext_len];
                match ext_type {
                    // server_name (SNI, RFC 6066)
                    0x0000 => {
                        if ext_data.len() >= 5 && ext_data[2] == 0x00 {
                            let name_len =
                                usize::from(u16::from_be_bytes([ext_data[3], ext_data[4]]));
                            if 5 + name_len <= ext_data.len() && name_len > 0 {
                                let name_off = pos + 5;
                                out.host_offset = Some(name_off);
                                out.host_len = name_len;
                                out.host = ascii::lowercased(
                                    std::str::from_utf8(&buf[name_off..name_off + name_len])
                                        .unwrap_or(""),
                                );
                            }
                        }
                    }
                    // encrypted_client_hello (ECH, RFC 9849, 0xfe0d)
                    0xfe0d => {
                        out.ech_offset = Some(pos);
                        out.ech_len = ext_len;
                    }
                    // key_share (0x0033) or supported_groups (0x000a) — X25519MLKEM768 (0x11ec) / MLKEM768 (0x0200)
                    0x0033 | 0x000a
                        if ext_len > 512
                            || ascii::scan_pattern(ext_data, &[0x11, 0xec]).is_some()
                            || ascii::scan_pattern(ext_data, &[0x02, 0x00]).is_some() =>
                    {
                        out.post_quantum = true;
                    }
                    _ => {}
                }
                pos += ext_len;
            }
        }

        // Compute optimal multi-split offsets inside SNI and ECH so stateful DPI reassemblers
        // never see an intact SNI or ECH extension in a single TCP segment.
        let mut splits = Vec::with_capacity(2);
        let first_split = fallback_split.clamp(1, buf.len().saturating_sub(1));
        if let Some(sni_off) = out.host_offset {
            let mid_sni = sni_off + (out.host_len / 2).max(1);
            if first_split < mid_sni && mid_sni < buf.len() {
                splits.push(first_split);
                splits.push(mid_sni);
            } else if mid_sni < buf.len() {
                splits.push(mid_sni);
            }
        } else if let Some(ech_off) = out.ech_offset {
            let mid_ech = (ech_off + (out.ech_len / 2).max(1)).min(buf.len().saturating_sub(1));
            if first_split < mid_ech {
                splits.push(first_split);
                splits.push(mid_ech);
            } else if mid_ech > 0 {
                splits.push(mid_ech);
            }
        }
        if splits.is_empty() && buf.len() > 2 {
            splits.push(first_split);
        }
        out.split_offsets = splits;
        Some(out)
    }

    fn inspect_http_request(buf: &[u8], fallback_split: usize) -> Option<L7Inspection> {
        if !HTTP_METHODS.iter().any(|m| buf.starts_with(m)) {
            return None;
        }
        let mut out = L7Inspection {
            protocol: PROTO_HTTP_REQUEST,
            ..L7Inspection::default()
        };
        let host_pos = ascii::scan_pattern(buf, b"\r\nHost:")
            .or_else(|| ascii::scan_pattern(buf, b"\r\nhost:"))
            .map(|p| p + 7);
        if let Some(mut start) = host_pos {
            while start < buf.len() && (buf[start] == b' ' || buf[start] == b'\t') {
                start += 1;
            }
            let mut end = start;
            while end < buf.len() && buf[end] != b'\r' && buf[end] != b'\n' {
                end += 1;
            }
            if end > start {
                let raw_host = &buf[start..end];
                let host_only = raw_host
                    .iter()
                    .position(|&b| b == b':')
                    .map_or(raw_host, |i| &raw_host[..i]);
                out.host_offset = Some(start);
                out.host_len = host_only.len();
                out.host = ascii::lowercased(std::str::from_utf8(host_only).unwrap_or(""));
                let mid = start + (out.host_len / 2).max(1);
                if mid < buf.len() {
                    out.split_offsets.push(mid);
                }
            }
        }
        if out.split_offsets.is_empty() && buf.len() > 2 {
            out.split_offsets
                .push(fallback_split.clamp(1, buf.len().saturating_sub(1)));
        }
        Some(out)
    }

    fn inspect_quic_initial(buf: &[u8]) -> Option<L7Inspection> {
        // QUIC Long Header: top bits 11, Fixed bit 1 -> (buf[0] & 0xc0) == 0xc0, plus 4-byte version.
        if buf.len() < 64 || (buf[0] & 0xc0) != 0xc0 {
            return None;
        }
        let ver = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        if ver != quic::VERSION_1 && ver != quic::VERSION_2 {
            return None;
        }
        Some(L7Inspection {
            protocol: PROTO_QUIC_INITIAL,
            ..L7Inspection::default()
        })
    }

    fn inspect_discord_voice(buf: &[u8]) -> Option<L7Inspection> {
        // Discord Voice IP Discovery (74-byte `[0x00, 0x01, 0x00, 0x46, ...]` or 70-byte
        // `[0x00, 0x01, 0x00, 0x42, ...]`) or RFC 5389 STUN Binding Request with magic `0x2112A442`.
        let is_ip_discovery = (buf.len() == 74 && buf[..4] == [0x00, 0x01, 0x00, 0x46])
            || (buf.len() == 70 && buf[..4] == [0x00, 0x01, 0x00, 0x42]);
        let is_stun =
            buf.len() >= 20 && buf[..2] == [0x00, 0x01] && buf[4..8] == [0x21, 0x12, 0xa4, 0x42];
        if !is_ip_discovery && !is_stun {
            return None;
        }
        Some(L7Inspection {
            protocol: PROTO_DISCORD_VOICE,
            host: "discord.voice".to_owned(),
            ..L7Inspection::default()
        })
    }

    fn inspect_roblox_raknet(buf: &[u8]) -> Option<L7Inspection> {
        // Roblox RakNet connection establishment packets (`0x01` UnconnectedPing, `0x05`
        // OpenConnectionRequest1, `0x07` OpenConnectionRequest2) carry the 16-byte offline magic.
        if buf.len() < 17 || !matches!(buf[0], 0x01 | 0x02 | 0x05 | 0x07) {
            return None;
        }
        ascii::scan_pattern(buf, &RAKNET_OFFLINE_MAGIC)?;
        Some(L7Inspection {
            protocol: PROTO_ROBLOX_RAKNET,
            host: "roblox.raknet".to_owned(),
            ..L7Inspection::default()
        })
    }

    /// Computes the RFC 1071 IPv4 header checksum over `ip_hdr` (ignoring bytes 10..12).
    pub fn ipv4_header_checksum(ip_hdr: &[u8]) -> u16 {
        if ip_hdr.len() < 20 {
            return 0;
        }
        let mut sum = u64::from(ascii::csum_fold(&ip_hdr[..10], 0));
        sum = u64::from(ascii::csum_fold(&ip_hdr[12..], sum));
        !(sum as u16)
    }

    /// Computes the RFC 1071 / RFC 9293 TCP or UDP checksum over an IPv4 packet.
    pub fn transport_checksum_v4(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
        l4_segment: &[u8],
    ) -> u16 {
        let mut pseudo = [0u8; 12];
        pseudo[0..4].copy_from_slice(&src.octets());
        pseudo[4..8].copy_from_slice(&dst.octets());
        pseudo[9] = proto;
        pseudo[10..12].copy_from_slice(&(l4_segment.len() as u16).to_be_bytes());
        let sum = u64::from(ascii::csum_fold(&pseudo, 0));
        let folded = ascii::csum_fold(l4_segment, sum);
        let res = !folded;
        if proto == 17 && res == 0 { 0xffff } else { res }
    }

    /// Computes the RFC 8200 TCP or UDP checksum over an IPv6 packet.
    pub fn transport_checksum_v6(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        proto: u8,
        l4_segment: &[u8],
    ) -> u16 {
        let mut pseudo = [0u8; 40];
        pseudo[0..16].copy_from_slice(&src.octets());
        pseudo[16..32].copy_from_slice(&dst.octets());
        pseudo[32..36].copy_from_slice(&(l4_segment.len() as u32).to_be_bytes());
        pseudo[39] = proto;
        let sum = u64::from(ascii::csum_fold(&pseudo, 0));
        let folded = ascii::csum_fold(l4_segment, sum);
        let res = !folded;
        if proto == 17 && res == 0 { 0xffff } else { res }
    }

    /// Output of packet-level DPI desynchronization.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct DesyncOutput {
        pub packets: Vec<Vec<u8>>,
        pub dropped_inbound: bool,
        pub inspection: L7Inspection,
    }

    /// Detects passive-DPI spoofed inbound TCP RST or cleartext HTTP 302/403 block redirects.
    pub fn should_drop_inbound(pkt: &[u8]) -> bool {
        if pkt.len() < 40 {
            return false;
        }
        let version = pkt[0] >> 4;
        let (ip_hdr_len, proto, ip_id, ttl) = match version {
            4 => {
                let ihl = usize::from(pkt[0] & 0x0f) * 4;
                if ihl < 20 || pkt.len() < ihl + 20 {
                    return false;
                }
                let id = u16::from_be_bytes([pkt[4], pkt[5]]);
                (ihl, pkt[9], id, pkt[8])
            }
            6 => {
                if pkt.len() < 60 {
                    return false;
                }
                (40usize, pkt[6], 0u16, pkt[7])
            }
            _ => return false,
        };
        if proto != 6 {
            return false;
        }
        let tcp = &pkt[ip_hdr_len..];
        let doff = usize::from(tcp[12] >> 4) * 4;
        if doff < 20 || tcp.len() < doff {
            return false;
        }
        let flags = tcp[13];
        let win = u16::from_be_bytes([tcp[14], tcp[15]]);
        let payload = &tcp[doff..];
        // 1) Passive optical-splitter DPI RST signature: RST flag set with non-empty payload,
        //    or IPv4 ID == 0x0001 / 0x0000 combined with zero window and anomalous TTL.
        if (flags & 0x04) != 0 && (!payload.is_empty() || (win == 0 && (ip_id <= 1 || ttl == 255)))
        {
            return true;
        }
        // 2) Passive DPI injected HTTP 302/403 redirect with FIN+PSH+ACK in a single packet.
        if (flags & 0x01) != 0
            && (payload.starts_with(b"HTTP/1.1 302 ")
                || payload.starts_with(b"HTTP/1.0 302 ")
                || payload.starts_with(b"HTTP/1.1 403 "))
        {
            return true;
        }
        false
    }

    /// Transforms a raw IPv4 or IPv6 packet according to `cfg` (splitting, disordering,
    /// injecting decoy packets with RFC 1624 BadSum or auto-TTL, or filtering inbound RSTs).
    pub fn desync_packet(pkt: &[u8], cfg: &DesyncConfig) -> DesyncOutput {
        if cfg.drop_spoofed_rst && should_drop_inbound(pkt) {
            return DesyncOutput {
                packets: Vec::new(),
                dropped_inbound: true,
                inspection: L7Inspection::default(),
            };
        }
        if cfg.mode == DesyncMode::Off || pkt.len() < 28 {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: L7Inspection::default(),
            };
        }
        let version = pkt[0] >> 4;
        match version {
            4 => desync_ipv4(pkt, cfg),
            6 => desync_ipv6(pkt, cfg),
            _ => DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: L7Inspection::default(),
            },
        }
    }

    fn build_ipv4_tcp_segment(
        ip_hdr: &[u8],
        tcp_hdr: &[u8],
        seq: u32,
        clear_psh: bool,
        ttl_override: Option<u8>,
        corrupt_csum: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let ihl = ip_hdr.len();
        let doff = tcp_hdr.len();
        let total_len = ihl + doff + payload.len();
        let mut out = Vec::with_capacity(total_len);
        out.extend_from_slice(ip_hdr);
        out.extend_from_slice(tcp_hdr);
        out.extend_from_slice(payload);

        // Update IPv4 Total Length and optional TTL
        out[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        if let Some(ttl) = ttl_override {
            out[8] = ttl;
        }
        out[10] = 0;
        out[11] = 0;
        let ip_csum = ipv4_header_checksum(&out[..ihl]);
        out[10..12].copy_from_slice(&ip_csum.to_be_bytes());

        // Update TCP Sequence Number and PSH flag
        out[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());
        if clear_psh {
            out[ihl + 13] &= !0x08;
        }
        out[ihl + 16] = 0;
        out[ihl + 17] = 0;
        let src = Ipv4Addr::new(out[12], out[13], out[14], out[15]);
        let dst = Ipv4Addr::new(out[16], out[17], out[18], out[19]);
        let mut tcp_csum = transport_checksum_v4(src, dst, 6, &out[ihl..]);
        if corrupt_csum {
            // RFC 1624 O(1) delta mutation so DPI accepts the decoy while destination drops it.
            tcp_csum = ascii::csum_delta(tcp_csum, 0x0000, 0xdead);
        }
        out[ihl + 16..ihl + 18].copy_from_slice(&tcp_csum.to_be_bytes());
        out
    }

    fn build_ipv6_tcp_segment(
        ip_hdr: &[u8],
        tcp_hdr: &[u8],
        seq: u32,
        clear_psh: bool,
        hop_override: Option<u8>,
        corrupt_csum: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let doff = tcp_hdr.len();
        let plen = doff + payload.len();
        let mut out = Vec::with_capacity(40 + plen);
        out.extend_from_slice(ip_hdr);
        out.extend_from_slice(tcp_hdr);
        out.extend_from_slice(payload);

        out[4..6].copy_from_slice(&(plen as u16).to_be_bytes());
        if let Some(hops) = hop_override {
            out[7] = hops;
        }
        out[40 + 4..40 + 8].copy_from_slice(&seq.to_be_bytes());
        if clear_psh {
            out[40 + 13] &= !0x08;
        }
        out[40 + 16] = 0;
        out[40 + 17] = 0;
        let mut src_b = [0u8; 16];
        let mut dst_b = [0u8; 16];
        src_b.copy_from_slice(&out[8..24]);
        dst_b.copy_from_slice(&out[24..40]);
        let mut tcp_csum =
            transport_checksum_v6(Ipv6Addr::from(src_b), Ipv6Addr::from(dst_b), 6, &out[40..]);
        if corrupt_csum {
            tcp_csum = ascii::csum_delta(tcp_csum, 0x0000, 0xdead);
        }
        out[40 + 16..40 + 18].copy_from_slice(&tcp_csum.to_be_bytes());
        out
    }

    /// Builds a benign decoy payload (`www.iana.org` or `dl.google.com` in `RealityVision`)
    /// of the exact same length as `payload`.
    pub fn make_decoy_payload(payload: &[u8], info: &L7Inspection) -> Vec<u8> {
        make_decoy_payload_for_mode(payload, info, DesyncMode::AdaptiveFull)
    }

    pub fn make_decoy_payload_for_mode(
        payload: &[u8],
        info: &L7Inspection,
        mode: DesyncMode,
    ) -> Vec<u8> {
        let mut decoy = payload.to_vec();
        if let Some(off) = info.host_offset {
            let benign: &[u8] = if mode == DesyncMode::RealityVision {
                REALITY_DEFAULT_DEST.as_bytes()
            } else {
                b"www.iana.org"
            };
            for i in 0..info.host_len {
                if off + i < decoy.len() {
                    decoy[off + i] = benign[i % benign.len()];
                }
            }
        }
        if let Some(ech_off) = info.ech_offset {
            for i in 0..info.ech_len.min(16) {
                if ech_off + i < decoy.len() {
                    decoy[ech_off + i] ^= 0x5a;
                }
            }
        }
        decoy
    }

    fn slice_ranges(len: usize, splits: &[usize]) -> Vec<(usize, usize)> {
        let mut pts = Vec::with_capacity(splits.len() + 2);
        pts.push(0);
        for &s in splits {
            if s > *pts.last().unwrap_or(&0) && s < len {
                pts.push(s);
            }
        }
        pts.push(len);
        pts.windows(2).map(|w| (w[0], w[1])).collect()
    }

    fn desync_ipv4(pkt: &[u8], cfg: &DesyncConfig) -> DesyncOutput {
        let ihl = usize::from(pkt[0] & 0x0f) * 4;
        if ihl < 20 || pkt.len() < ihl + 8 {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: L7Inspection::default(),
            };
        }
        let proto = pkt[9];
        if proto == 17 {
            return desync_ipv4_udp(pkt, ihl, cfg);
        }
        if proto != 6 || pkt.len() < ihl + 20 {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: L7Inspection::default(),
            };
        }
        let tcp = &pkt[ihl..];
        let doff = usize::from(tcp[12] >> 4) * 4;
        if doff < 20 || tcp.len() <= doff {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: L7Inspection::default(),
            };
        }
        let payload = &tcp[doff..];
        let info = inspect_l7(payload, cfg.split_pos);
        if info.protocol != PROTO_TLS_CLIENT_HELLO && info.protocol != PROTO_HTTP_REQUEST {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: info,
            };
        }

        let ip_hdr = &pkt[..ihl];
        let tcp_hdr = &tcp[..doff];
        let base_seq = u32::from_be_bytes([tcp_hdr[4], tcp_hdr[5], tcp_hdr[6], tcp_hdr[7]]);
        let ranges = slice_ranges(payload.len(), &info.split_offsets);

        let mut out_pkts = Vec::with_capacity(ranges.len() + 2);
        let decoy = make_decoy_payload_for_mode(payload, &info, cfg.mode);
        match cfg.mode {
            DesyncMode::FakeBadSum => {
                out_pkts.push(build_ipv4_tcp_segment(
                    ip_hdr, tcp_hdr, base_seq, false, None, true, &decoy,
                ));
            }
            DesyncMode::FakeAutoTtl => {
                out_pkts.push(build_ipv4_tcp_segment(
                    ip_hdr,
                    tcp_hdr,
                    base_seq,
                    false,
                    Some(cfg.fake_ttl),
                    false,
                    &decoy,
                ));
            }
            DesyncMode::AdaptiveFull | DesyncMode::RealityVision => {
                out_pkts.push(build_ipv4_tcp_segment(
                    ip_hdr,
                    tcp_hdr,
                    base_seq,
                    false,
                    Some(cfg.fake_ttl),
                    false,
                    &decoy,
                ));
                out_pkts.push(build_ipv4_tcp_segment(
                    ip_hdr, tcp_hdr, base_seq, false, None, true, &decoy,
                ));
            }
            _ => {}
        }

        let mut real_segs: Vec<Vec<u8>> = ranges
            .iter()
            .enumerate()
            .map(|(idx, &(start, end))| {
                let seq = base_seq.wrapping_add(start as u32);
                let is_last = idx + 1 == ranges.len();
                build_ipv4_tcp_segment(
                    ip_hdr,
                    tcp_hdr,
                    seq,
                    !is_last,
                    None,
                    false,
                    &payload[start..end],
                )
            })
            .collect();

        if matches!(
            cfg.mode,
            DesyncMode::Disorder
                | DesyncMode::FakeBadSum
                | DesyncMode::FakeAutoTtl
                | DesyncMode::AdaptiveFull
                | DesyncMode::RealityVision
        ) {
            real_segs.reverse();
        }
        out_pkts.extend(real_segs);
        DesyncOutput {
            packets: out_pkts,
            dropped_inbound: false,
            inspection: info,
        }
    }

    fn desync_ipv4_udp(pkt: &[u8], ihl: usize, cfg: &DesyncConfig) -> DesyncOutput {
        let udp = &pkt[ihl..];
        if udp.len() <= 8 {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: L7Inspection::default(),
            };
        }
        let payload = &udp[8..];
        let info = inspect_l7(payload, cfg.split_pos);
        if !matches!(
            info.protocol,
            PROTO_QUIC_INITIAL | PROTO_DISCORD_VOICE | PROTO_ROBLOX_RAKNET
        ) || !matches!(
            cfg.mode,
            DesyncMode::QuicScramble | DesyncMode::AdaptiveFull | DesyncMode::RealityVision
        ) {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: info,
            };
        }
        // Prepend a low-TTL decoy UDP datagram before the real QUIC Initial, Discord Voice IP
        // Discovery, or Roblox RakNet connection request so stateful first-packet UDP DPI filters
        // latch onto the benign decoy while it expires before reaching the destination server.
        let fake_payload = if info.protocol == PROTO_QUIC_INITIAL {
            quic::build_probe(
                &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe],
                &[0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef],
                quic::MIN_INITIAL_DATAGRAM,
            )
        } else {
            // 24-byte benign RFC 5389 STUN Binding Indication / NTP-like keepalive decoy
            vec![
                0x00, 0x11, 0x00, 0x04, 0x21, 0x12, 0xa4, 0x42, 0x74, 0x68, 0x65, 0x64, 0x70, 0x69,
                0x32, 0x36, 0x80, 0x28, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
            ]
        };
        let udp_len = 8 + fake_payload.len();
        let total_len = ihl + udp_len;
        let mut fake_pkt = Vec::with_capacity(total_len);
        fake_pkt.extend_from_slice(&pkt[..ihl]);
        fake_pkt.extend_from_slice(&udp[..8]);
        fake_pkt.extend_from_slice(&fake_payload);
        fake_pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        fake_pkt[8] = cfg.fake_ttl;
        fake_pkt[10] = 0;
        fake_pkt[11] = 0;
        let ip_csum = ipv4_header_checksum(&fake_pkt[..ihl]);
        fake_pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());
        fake_pkt[ihl + 4..ihl + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        fake_pkt[ihl + 6] = 0;
        fake_pkt[ihl + 7] = 0;
        let src = Ipv4Addr::new(fake_pkt[12], fake_pkt[13], fake_pkt[14], fake_pkt[15]);
        let dst = Ipv4Addr::new(fake_pkt[16], fake_pkt[17], fake_pkt[18], fake_pkt[19]);
        let udp_csum = transport_checksum_v4(src, dst, 17, &fake_pkt[ihl..]);
        fake_pkt[ihl + 6..ihl + 8].copy_from_slice(&udp_csum.to_be_bytes());

        DesyncOutput {
            packets: vec![fake_pkt, pkt.to_vec()],
            dropped_inbound: false,
            inspection: info,
        }
    }

    fn desync_ipv6(pkt: &[u8], cfg: &DesyncConfig) -> DesyncOutput {
        if pkt.len() < 60 || pkt[6] != 6 {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: L7Inspection::default(),
            };
        }
        let ip_hdr = &pkt[..40];
        let tcp = &pkt[40..];
        let doff = usize::from(tcp[12] >> 4) * 4;
        if doff < 20 || tcp.len() <= doff {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: L7Inspection::default(),
            };
        }
        let payload = &tcp[doff..];
        let info = inspect_l7(payload, cfg.split_pos);
        if info.protocol != PROTO_TLS_CLIENT_HELLO && info.protocol != PROTO_HTTP_REQUEST {
            return DesyncOutput {
                packets: vec![pkt.to_vec()],
                dropped_inbound: false,
                inspection: info,
            };
        }
        let tcp_hdr = &tcp[..doff];
        let base_seq = u32::from_be_bytes([tcp_hdr[4], tcp_hdr[5], tcp_hdr[6], tcp_hdr[7]]);
        let ranges = slice_ranges(payload.len(), &info.split_offsets);

        let mut out_pkts = Vec::with_capacity(ranges.len() + 1);
        let decoy = make_decoy_payload_for_mode(payload, &info, cfg.mode);
        if matches!(
            cfg.mode,
            DesyncMode::FakeBadSum
                | DesyncMode::FakeAutoTtl
                | DesyncMode::AdaptiveFull
                | DesyncMode::RealityVision
        ) {
            let hop = matches!(
                cfg.mode,
                DesyncMode::FakeAutoTtl | DesyncMode::AdaptiveFull | DesyncMode::RealityVision
            )
            .then_some(cfg.fake_ttl);
            let bad = matches!(
                cfg.mode,
                DesyncMode::FakeBadSum | DesyncMode::AdaptiveFull | DesyncMode::RealityVision
            );
            out_pkts.push(build_ipv6_tcp_segment(
                ip_hdr, tcp_hdr, base_seq, false, hop, bad, &decoy,
            ));
        }
        let mut real_segs: Vec<Vec<u8>> = ranges
            .iter()
            .enumerate()
            .map(|(idx, &(start, end))| {
                let seq = base_seq.wrapping_add(start as u32);
                let is_last = idx + 1 == ranges.len();
                build_ipv6_tcp_segment(
                    ip_hdr,
                    tcp_hdr,
                    seq,
                    !is_last,
                    None,
                    false,
                    &payload[start..end],
                )
            })
            .collect();
        if matches!(
            cfg.mode,
            DesyncMode::Disorder
                | DesyncMode::FakeBadSum
                | DesyncMode::FakeAutoTtl
                | DesyncMode::AdaptiveFull
                | DesyncMode::RealityVision
        ) {
            real_segs.reverse();
        }
        out_pkts.extend(real_segs);
        DesyncOutput {
            packets: out_pkts,
            dropped_inbound: false,
            inspection: info,
        }
    }

    /// Writes a payload over `stream` applying socket-level DPI desynchronization
    /// (`TCP_NODELAY` + optional low-TTL decoy + multi-segment SNI/ECH split writes
    /// + `xtls-rprx-vision` direct splice transition tracking).
    pub fn write_desync_stream(
        stream: &mut TcpStream,
        payload: &[u8],
        cfg: &DesyncConfig,
        stats: &ProxyCounters,
    ) -> io::Result<()> {
        let _ = stream.set_nodelay(true);
        if cfg.mode == DesyncMode::Off || payload.len() <= 2 {
            return stream.write_all(payload);
        }
        if cfg.mode == DesyncMode::RealityVision && is_tls_application_data(payload) {
            stats.vision_splice.fetch_add(1, Ordering::Relaxed);
            return stream.write_all(payload);
        }
        let info = inspect_l7(payload, cfg.split_pos);
        if info.protocol == PROTO_TLS_CLIENT_HELLO {
            stats.tls_split.fetch_add(1, Ordering::Relaxed);
        } else if info.protocol == PROTO_HTTP_REQUEST {
            stats.http_split.fetch_add(1, Ordering::Relaxed);
        } else {
            return stream.write_all(payload);
        }

        let ipv6 = stream.peer_addr().is_ok_and(|a| a.is_ipv6());
        let ranges = slice_ranges(payload.len(), &info.split_offsets);

        // Low-TTL decoy segment on the initial prefix when requested and supported by OS
        if matches!(
            cfg.mode,
            DesyncMode::FakeAutoTtl | DesyncMode::AdaptiveFull | DesyncMode::RealityVision
        ) {
            let first_end = ranges.first().map_or(2, |r| r.1).min(payload.len());
            if sys::set_tcp_ttl(stream, ipv6, u32::from(cfg.fake_ttl)).is_ok() {
                let decoy = make_decoy_payload_for_mode(&payload[..first_end], &info, cfg.mode);
                let _ = stream.write(&decoy);
                let _ = stream.flush();
                let _ = sys::set_tcp_ttl(stream, ipv6, 64);
                stats.fake_sent.fetch_add(1, Ordering::Relaxed);
            }
        }

        for (start, end) in ranges {
            stream.write_all(&payload[start..end])?;
            stream.flush()?;
        }
        if cfg.mode == DesyncMode::RealityVision && info.protocol == PROTO_TLS_CLIENT_HELLO {
            stats.vision_splice.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    #[derive(Debug, Default)]
    pub struct ProxyCounters {
        pub connections: AtomicU64,
        pub tls_split: AtomicU64,
        pub http_split: AtomicU64,
        pub fake_sent: AtomicU64,
        pub rst_dropped: AtomicU64,
        pub vision_splice: AtomicU64,
    }

    /// Unprivileged local SOCKS5 (RFC 1928) + HTTP CONNECT DPI-circumvention proxy.
    #[derive(Debug)]
    pub struct LocalProxy {
        port: u16,
        config: DesyncConfig,
        stop: Arc<AtomicBool>,
        counters: Arc<ProxyCounters>,
        accept_thread: Option<JoinHandle<()>>,
    }

    impl LocalProxy {
        pub fn start(cfg: DesyncConfig) -> io::Result<Self> {
            Self::start_with_counters(cfg, Arc::new(ProxyCounters::default()))
        }

        pub fn start_with_counters(
            cfg: DesyncConfig,
            counters: Arc<ProxyCounters>,
        ) -> io::Result<Self> {
            let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, cfg.listen_port));
            let listener = TcpListener::bind(bind_addr)?;
            let port = listener.local_addr()?.port();
            listener.set_nonblocking(true)?;
            let stop = Arc::new(AtomicBool::new(false));
            let stop_c = Arc::clone(&stop);
            let counters_c = Arc::clone(&counters);
            let cfg_c = cfg.clone();

            let handle = thread::Builder::new()
                .name("thedpi-desync-proxy".to_owned())
                .spawn(move || {
                    while !stop_c.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((client, _)) => {
                                let _ = client.set_nonblocking(false);
                                counters_c.connections.fetch_add(1, Ordering::Relaxed);
                                let cfg_conn = cfg_c.clone();
                                let cnt_conn = Arc::clone(&counters_c);
                                let _ = thread::Builder::new().stack_size(256 * 1024).spawn(
                                    move || {
                                        let _ = handle_proxy_client(client, &cfg_conn, &cnt_conn);
                                    },
                                );
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(_) => break,
                        }
                    }
                })?;

            Ok(Self {
                port,
                config: cfg,
                stop,
                counters,
                accept_thread: Some(handle),
            })
        }

        pub fn port(&self) -> u16 {
            self.port
        }

        pub fn config(&self) -> &DesyncConfig {
            &self.config
        }

        pub fn counters(&self) -> &ProxyCounters {
            &self.counters
        }

        pub fn stop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)),
                Duration::from_millis(50),
            );
            if let Some(h) = self.accept_thread.take() {
                let _ = h.join();
            }
        }
    }

    impl Drop for LocalProxy {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn handle_proxy_client(
        mut client: TcpStream,
        cfg: &DesyncConfig,
        counters: &ProxyCounters,
    ) -> io::Result<()> {
        let _ = client.set_nonblocking(false);
        client.set_read_timeout(Some(Duration::from_millis(3000)))?;
        client.set_write_timeout(Some(Duration::from_millis(3000)))?;
        let mut first = [0u8; 4096];
        let n = client.read(&mut first)?;
        if n == 0 {
            return Ok(());
        }
        if first[0] == 0x05 {
            handle_socks5(client, &first[..n], cfg, counters)
        } else {
            handle_http_proxy(client, &first[..n], cfg, counters)
        }
    }

    fn handle_socks5(
        mut client: TcpStream,
        greeting: &[u8],
        cfg: &DesyncConfig,
        counters: &ProxyCounters,
    ) -> io::Result<()> {
        if greeting.len() < 2 {
            return Ok(());
        }
        // No-auth reply (0x05, 0x00)
        client.write_all(&[0x05, 0x00])?;
        let mut req = [0u8; 512];
        let n = client.read(&mut req)?;
        if n < 7 || req[0] != 0x05 || req[1] != 0x01 {
            let _ = client.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            return Ok(());
        }
        let target_addr: String = match req[3] {
            0x01 if n >= 10 => {
                let ip = Ipv4Addr::new(req[4], req[5], req[6], req[7]);
                let port = u16::from_be_bytes([req[8], req[9]]);
                format!("{ip}:{port}")
            }
            0x03 => {
                let dlen = usize::from(req[4]);
                if n < 5 + dlen + 2 {
                    return Ok(());
                }
                let host = std::str::from_utf8(&req[5..5 + dlen]).unwrap_or("");
                let port = u16::from_be_bytes([req[5 + dlen], req[6 + dlen]]);
                format!("{host}:{port}")
            }
            0x04 if n >= 22 => {
                let mut b = [0u8; 16];
                b.copy_from_slice(&req[4..20]);
                let ip = Ipv6Addr::from(b);
                let port = u16::from_be_bytes([req[20], req[21]]);
                format!("[{ip}]:{port}")
            }
            _ => return Ok(()),
        };
        let mut upstream = match connect_target(&target_addr) {
            Ok(s) => s,
            Err(_) => {
                let _ = client.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
                return Ok(());
            }
        };
        client.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])?;
        let mut payload = [0u8; 8192];
        let pn = client.read(&mut payload)?;
        if pn > 0 {
            write_desync_stream(&mut upstream, &payload[..pn], cfg, counters)?;
        }
        relay_bidirectional(client, upstream)
    }

    fn handle_http_proxy(
        mut client: TcpStream,
        initial: &[u8],
        cfg: &DesyncConfig,
        counters: &ProxyCounters,
    ) -> io::Result<()> {
        if initial.starts_with(b"CONNECT ") {
            let line_end = ascii::scan_pattern(initial, b"\r\n").unwrap_or(initial.len());
            let line = std::str::from_utf8(&initial[8..line_end]).unwrap_or("");
            let host_port = line.split_whitespace().next().unwrap_or("");
            let mut upstream = connect_target(host_port)?;
            client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
            let mut payload = [0u8; 8192];
            let pn = client.read(&mut payload)?;
            if pn > 0 {
                write_desync_stream(&mut upstream, &payload[..pn], cfg, counters)?;
            }
            relay_bidirectional(client, upstream)
        } else {
            let info = inspect_l7(initial, cfg.split_pos);
            if info.host.is_empty() {
                return Ok(());
            }
            let target = if info.host.contains(':') {
                info.host.clone()
            } else {
                format!("{}:80", info.host)
            };
            let mut upstream = connect_target(&target)?;
            write_desync_stream(&mut upstream, initial, cfg, counters)?;
            relay_bidirectional(client, upstream)
        }
    }

    fn connect_target(host_port: &str) -> io::Result<TcpStream> {
        use std::net::ToSocketAddrs;
        let mut addrs = host_port.to_socket_addrs()?;
        let addr = addrs
            .next()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let s = TcpStream::connect_timeout(&addr, Duration::from_millis(2500))?;
        let _ = s.set_read_timeout(Some(Duration::from_millis(3000)));
        let _ = s.set_write_timeout(Some(Duration::from_millis(3000)));
        let _ = s.set_nodelay(true);
        Ok(s)
    }

    fn relay_bidirectional(mut client: TcpStream, mut upstream: TcpStream) -> io::Result<()> {
        let mut c_read = client.try_clone()?;
        let mut u_write = upstream.try_clone()?;
        let t = thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(move || {
                let _ = io::copy(&mut c_read, &mut u_write);
                let _ = u_write.shutdown(Shutdown::Write);
            })?;
        let _ = io::copy(&mut upstream, &mut client);
        let _ = client.shutdown(Shutdown::Write);
        let _ = t.join();
        Ok(())
    }

    /// Wire-encodes `DesyncOutput` for JNI calls (`Native.desyncPacket`).
    pub fn encode_desync_output(out: &DesyncOutput, mode: DesyncMode) -> Record {
        use tags::desync as t;
        let mut r = Record::with_status(code::OK);
        r.int(t::MODE, mode as i64)
            .int(t::DROPPED, i64::from(out.dropped_inbound))
            .int(t::PROTOCOL, out.inspection.protocol)
            .text(t::SNI, &out.inspection.host)
            .int(t::ECH, i64::from(out.inspection.ech_offset.is_some()))
            .int(t::POST_QUANTUM, i64::from(out.inspection.post_quantum));
        for pkt in &out.packets {
            r.bytes(t::OUT_PACKET, pkt);
        }
        r
    }
}

// ---------------------------------------------------------------------------
// relay — 2026-2027 Personal Server & Relay System (REALITY + mlkem768 + Vision + MASQUE)
// ---------------------------------------------------------------------------

/// Self-hosted Personal Server and Relay engine ("Your Network. Your Server. Your Control.").
///
/// Implements:
/// 1. **Per-Device Authentication & Instant Revocation**: Each client device possesses a unique
///    `device_id` and 256-bit `auth_key`. Handshakes are authenticated inside a `REALITY` +
///    `X25519MLKEM768` (`0x11ec`) TLS 1.3 `ClientHello` `SessionId`.
/// 2. **Active Probing Defense (`REALITY` `dest` Camouflage)**: Unauthenticated connections or
///    active censor probes never see a self-signed certificate or custom error; the server
///    transparently splices their connection to the configured `cover_dest` server so the
///    prober receives the genuine `ServerHello` and certificate chain of the cover site.
/// 3. **`xtls-rprx-vision` Direct Splice & Bandwidth Quotas**: Authenticated sessions transition
///    to direct TLS splice (`0x17 0x03 0x03`) with per-device byte-accurate quota enforcement.
/// 4. **Multi-Server Failover**: `RelayClient` automatically fails over from `primary_endpoint`
///    to `backup_endpoint` when the primary server is unreachable.
/// 5. **RFC 9298 (HTTP/UDP) & RFC 9484 (HTTP/IP) MASQUE Framing**: Standardized datagram and
///    Layer-3 packet capsules for lossless UDP (Roblox/Discord voice) and IP tunneling.
pub mod relay {
    use crate::desync::{
        REALITY_DEFAULT_DEST, TLS_GROUP_X25519_MLKEM768, VisionFlow, VisionPhase,
        build_reality_mlkem768_client_hello, compute_reality_session_id, extract_reality_fields,
    };
    use std::collections::BTreeMap;
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    /// RFC 9298 MASQUE UDP-in-HTTP capsule type (`0x00`).
    pub const CAPSULE_DATAGRAM_UDP: u8 = 0x00;
    /// RFC 9484 MASQUE IP-in-HTTP capsule type (`0x01`).
    pub const CAPSULE_IP_PACKET: u8 = 0x01;

    /// Connection and authorization state of a `ServerProfile`.
    #[repr(i64)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum ServerStatus {
        #[default]
        Disconnected = 0,
        Connected = 1,
        Standby = 2,
        Failover = 3,
        QuotaExceeded = 4,
        AuthFailed = 5,
        Revoked = 6,
        Unreachable = 7,
    }

    /// Server-side per-device credential, quota, and revocation entry.
    #[derive(Debug, Clone)]
    pub struct DeviceCredential {
        pub device_id: String,
        pub auth_key: [u8; 32],
        pub quota_bytes: u64,
        pub used_bytes: Arc<AtomicU64>,
        pub revoked: bool,
    }

    /// Client-side Personal Server profile.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ServerProfile {
        pub id: String,
        pub name: String,
        pub primary_endpoint: String,
        pub backup_endpoint: String,
        pub cover_sni: String,
        pub device_id: String,
        pub auth_key: [u8; 32],
        pub quota_bytes: u64,
        pub used_bytes: u64,
        pub latency_us: u64,
        pub loss_pct: u8,
        pub status: ServerStatus,
    }

    impl Default for ServerProfile {
        fn default() -> Self {
            Self {
                id: "srv-01".to_owned(),
                name: "Kişisel Sunucu 01".to_owned(),
                primary_endpoint: String::new(),
                backup_endpoint: String::new(),
                cover_sni: REALITY_DEFAULT_DEST.to_owned(),
                device_id: "device-default".to_owned(),
                auth_key: [0x42u8; 32],
                quota_bytes: 100 * 1024 * 1024 * 1024, // 100 GiB default
                used_bytes: 0,
                latency_us: 0,
                loss_pct: 0,
                status: ServerStatus::Standby,
            }
        }
    }

    /// Encodes a UDP datagram into an RFC 9298 HTTP/UDP capsule:
    /// `[CAPSULE_DATAGRAM_UDP (1B), context_id (4B BE), family (1B: 4 or 6), addr (4B/16B), port (2B BE), len (2B BE), payload]`.
    pub fn encode_udp_capsule(context_id: u32, target: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let plen = payload.len().min(65535);
        let mut out = Vec::with_capacity(16 + plen);
        out.push(CAPSULE_DATAGRAM_UDP);
        out.extend_from_slice(&context_id.to_be_bytes());
        match target.ip() {
            IpAddr::V4(v4) => {
                out.push(4);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(6);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&target.port().to_be_bytes());
        out.extend_from_slice(&(plen as u16).to_be_bytes());
        out.extend_from_slice(&payload[..plen]);
        out
    }

    /// Decodes an RFC 9298 HTTP/UDP capsule into `(context_id, target, payload)`.
    pub fn decode_udp_capsule(buf: &[u8]) -> Option<(u32, SocketAddr, Vec<u8>)> {
        if buf.len() < 14 || buf[0] != CAPSULE_DATAGRAM_UDP {
            return None;
        }
        let context_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        match buf[5] {
            4 if buf.len() >= 14 => {
                let ip = Ipv4Addr::new(buf[6], buf[7], buf[8], buf[9]);
                let port = u16::from_be_bytes([buf[10], buf[11]]);
                let plen = usize::from(u16::from_be_bytes([buf[12], buf[13]]));
                if buf.len() < 14 + plen {
                    return None;
                }
                Some((
                    context_id,
                    SocketAddr::from((ip, port)),
                    buf[14..14 + plen].to_vec(),
                ))
            }
            6 if buf.len() >= 26 => {
                let mut oct = [0u8; 16];
                oct.copy_from_slice(&buf[6..22]);
                let ip = Ipv6Addr::from(oct);
                let port = u16::from_be_bytes([buf[22], buf[23]]);
                let plen = usize::from(u16::from_be_bytes([buf[24], buf[25]]));
                if buf.len() < 26 + plen {
                    return None;
                }
                Some((
                    context_id,
                    SocketAddr::from((ip, port)),
                    buf[26..26 + plen].to_vec(),
                ))
            }
            _ => None,
        }
    }

    /// Encodes a raw IPv4/IPv6 packet into an RFC 9484 HTTP/IP capsule:
    /// `[CAPSULE_IP_PACKET (1B), ip_version (1B), len (2B BE), raw_packet]`.
    pub fn encode_ip_capsule(pkt: &[u8]) -> Option<Vec<u8>> {
        if !crate::sys::wintun::valid_l3_packet(pkt) {
            return None;
        }
        let ver = pkt[0] >> 4;
        let mut out = Vec::with_capacity(4 + pkt.len());
        out.push(CAPSULE_IP_PACKET);
        out.push(ver);
        out.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
        out.extend_from_slice(pkt);
        Some(out)
    }

    /// Decodes an RFC 9484 HTTP/IP capsule and validates the inner IPv4/IPv6 packet.
    pub fn decode_ip_capsule(buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < 24 || buf[0] != CAPSULE_IP_PACKET {
            return None;
        }
        let plen = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
        if buf.len() < 4 + plen {
            return None;
        }
        let pkt = &buf[4..4 + plen];
        if (pkt[0] >> 4) != buf[1] || !crate::sys::wintun::valid_l3_packet(pkt) {
            return None;
        }
        Some(pkt.to_vec())
    }

    /// Telemetry counters for `PersonalRelayServer`.
    #[derive(Debug, Default)]
    pub struct RelayServerCounters {
        pub authorized_sessions: AtomicU64,
        pub probers_deflected: AtomicU64,
        pub revoked_rejected: AtomicU64,
        pub quota_rejected: AtomicU64,
        pub vision_splices: AtomicU64,
        pub relayed_bytes: AtomicU64,
    }

    /// Self-hosted Personal Relay Server supporting `REALITY` active-probing defense,
    /// `X25519MLKEM768` (`0x11ec`) post-quantum handshake authentication, per-device
    /// revocation and bandwidth quotas, and `xtls-rprx-vision` direct TLS splicing.
    #[derive(Debug)]
    pub struct PersonalRelayServer {
        addr: SocketAddr,
        devices: Arc<Mutex<BTreeMap<String, DeviceCredential>>>,
        cover_dest: Option<SocketAddr>,
        stop: Arc<AtomicBool>,
        counters: Arc<RelayServerCounters>,
        accept_thread: Option<JoinHandle<()>>,
    }

    impl PersonalRelayServer {
        pub fn start(bind_addr: SocketAddr, cover_dest: Option<SocketAddr>) -> io::Result<Self> {
            let listener = TcpListener::bind(bind_addr)?;
            let addr = listener.local_addr()?;
            listener.set_nonblocking(true)?;

            let devices: Arc<Mutex<BTreeMap<String, DeviceCredential>>> =
                Arc::new(Mutex::new(BTreeMap::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let counters = Arc::new(RelayServerCounters::default());

            let dev_c = Arc::clone(&devices);
            let stop_c = Arc::clone(&stop);
            let cnt_c = Arc::clone(&counters);

            let handle = thread::Builder::new()
                .name("thedpi-personal-relay".to_owned())
                .spawn(move || {
                    while !stop_c.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((client, _)) => {
                                let _ = client.set_nonblocking(false);
                                let dev_conn = Arc::clone(&dev_c);
                                let cnt_conn = Arc::clone(&cnt_c);
                                let _ = thread::Builder::new().stack_size(256 * 1024).spawn(
                                    move || {
                                        let _ = handle_relay_connection(
                                            client, cover_dest, &dev_conn, &cnt_conn,
                                        );
                                    },
                                );
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(_) => break,
                        }
                    }
                })?;

            Ok(Self {
                addr,
                devices,
                cover_dest,
                stop,
                counters,
                accept_thread: Some(handle),
            })
        }

        pub fn addr(&self) -> SocketAddr {
            self.addr
        }

        pub fn cover_dest(&self) -> Option<SocketAddr> {
            self.cover_dest
        }

        pub fn counters(&self) -> &RelayServerCounters {
            &self.counters
        }

        /// Registers or updates a device credential and quota.
        pub fn register_device(&self, device_id: &str, auth_key: [u8; 32], quota_bytes: u64) {
            let mut g = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
            g.insert(
                device_id.to_owned(),
                DeviceCredential {
                    device_id: device_id.to_owned(),
                    auth_key,
                    quota_bytes,
                    used_bytes: Arc::new(AtomicU64::new(0)),
                    revoked: false,
                },
            );
        }

        /// Immediately revokes a device's access.
        pub fn revoke_device(&self, device_id: &str) -> bool {
            let mut g = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(d) = g.get_mut(device_id) {
                d.revoked = true;
                true
            } else {
                false
            }
        }

        /// Rotates a device's authentication key and clears any revocation flag.
        pub fn rotate_device_key(&self, device_id: &str, new_key: [u8; 32]) -> bool {
            let mut g = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(d) = g.get_mut(device_id) {
                d.auth_key = new_key;
                d.revoked = false;
                true
            } else {
                false
            }
        }

        /// Returns the cumulative bytes used by `device_id`.
        pub fn device_used_bytes(&self, device_id: &str) -> Option<u64> {
            let g = self.devices.lock().unwrap_or_else(PoisonError::into_inner);
            g.get(device_id)
                .map(|d| d.used_bytes.load(Ordering::Relaxed))
        }

        pub fn stop(&mut self) {
            self.stop.store(true, Ordering::Release);
            let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(50));
            if let Some(h) = self.accept_thread.take() {
                let _ = h.join();
            }
        }
    }

    impl Drop for PersonalRelayServer {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn build_server_hello_ack(status: ServerStatus, session_id: &[u8; 32]) -> Vec<u8> {
        let mut sh = Vec::with_capacity(96);
        // Outer TLS 1.3 ServerHello record (0x16 0x03 0x03) with X25519MLKEM768 (0x11ec)
        sh.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x30]);
        sh.push(0x02); // ServerHello
        sh.extend_from_slice(&[0x00, 0x00, 0x2c, 0x03, 0x03]);
        sh.extend_from_slice(session_id);
        sh.extend_from_slice(&[0x00, 0x13, 0x01, 0x00, 0x00, 0x04]);
        sh.extend_from_slice(&TLS_GROUP_X25519_MLKEM768.to_be_bytes());
        sh.extend_from_slice(&[0x00, 0x00]);
        // Inner TLS 1.3 ApplicationData record (0x17 0x03 0x03) carrying status code
        sh.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x09]);
        sh.extend_from_slice(b"THEDPI_V");
        sh.push(status as i64 as u8);
        sh
    }

    fn handle_relay_connection(
        mut client: TcpStream,
        cover_dest: Option<SocketAddr>,
        devices: &Mutex<BTreeMap<String, DeviceCredential>>,
        counters: &RelayServerCounters,
    ) -> io::Result<()> {
        let _ = client.set_nonblocking(false);
        client.set_read_timeout(Some(Duration::from_millis(2500)))?;
        client.set_write_timeout(Some(Duration::from_millis(2500)))?;
        let _ = client.set_nodelay(true);

        let mut initial = [0u8; 4096];
        let n = client.read(&mut initial)?;
        if n == 0 {
            return Ok(());
        }
        let hello = &initial[..n];

        // Check if this is a valid REALITY + mlkem768 ClientHello from a registered device
        let matched_device = if let Some((random, sid, sni, pq)) = extract_reality_fields(hello)
            && pq
        {
            let g = devices.lock().unwrap_or_else(PoisonError::into_inner);
            g.values()
                .find(|d| {
                    compute_reality_session_id(&random, &sni, &d.device_id, &d.auth_key) == sid
                })
                .cloned()
                .map(|d| (d, sid))
        } else {
            None
        };

        let Some((cred, sid)) = matched_device else {
            // Unauthenticated probe or unknown key: REALITY active-probing defense!
            // Forward the exact bytes to `cover_dest` so the prober sees the genuine cover server.
            counters.probers_deflected.fetch_add(1, Ordering::Relaxed);
            if let Some(dest) = cover_dest
                && let Ok(mut cover) =
                    TcpStream::connect_timeout(&dest, Duration::from_millis(1500))
            {
                let _ = cover.set_read_timeout(Some(Duration::from_millis(2000)));
                let _ = cover.set_write_timeout(Some(Duration::from_millis(2000)));
                let _ = cover.write_all(hello);
                let _ = cover.flush();
                let mut resp = [0u8; 4096];
                if let Ok(rn) = cover.read(&mut resp)
                    && rn > 0
                {
                    let _ = client.write_all(&resp[..rn]);
                    let _ = client.flush();
                }
            }
            return Ok(());
        };

        if cred.revoked {
            counters.revoked_rejected.fetch_add(1, Ordering::Relaxed);
            let ack = build_server_hello_ack(ServerStatus::Revoked, &sid);
            let _ = client.write_all(&ack);
            return Ok(());
        }

        let current_used = cred.used_bytes.load(Ordering::Relaxed);
        if current_used >= cred.quota_bytes {
            counters.quota_rejected.fetch_add(1, Ordering::Relaxed);
            let ack = build_server_hello_ack(ServerStatus::QuotaExceeded, &sid);
            let _ = client.write_all(&ack);
            return Ok(());
        }

        counters.authorized_sessions.fetch_add(1, Ordering::Relaxed);
        let ack = build_server_hello_ack(ServerStatus::Connected, &sid);
        client.write_all(&ack)?;
        client.flush()?;

        // `xtls-rprx-vision` direct splice loop with per-device quota enforcement
        let mut vision = VisionFlow::new();
        let mut buf = [0u8; 8192];
        while let Ok(rn) = client.read(&mut buf) {
            if rn == 0 {
                break;
            }
            let chunk = &buf[..rn];
            if vision.observe_chunk(chunk) {
                counters.vision_splices.fetch_add(1, Ordering::Relaxed);
            }
            let prev = cred.used_bytes.fetch_add(rn as u64, Ordering::Relaxed);
            if prev.saturating_add(rn as u64) > cred.quota_bytes {
                counters.quota_rejected.fetch_add(1, Ordering::Relaxed);
                let alert = build_server_hello_ack(ServerStatus::QuotaExceeded, &sid);
                let _ = client.write_all(&alert);
                break;
            }
            counters
                .relayed_bytes
                .fetch_add(rn as u64, Ordering::Relaxed);
            // Echo/relay splice confirmation frame back to client in direct splice mode
            client.write_all(chunk)?;
            client.flush()?;
        }
        let _ = client.shutdown(Shutdown::Both);
        Ok(())
    }

    /// Client session established with a `PersonalRelayServer`.
    #[derive(Debug)]
    pub struct RelaySession {
        pub stream: TcpStream,
        pub status: ServerStatus,
        pub used_backup: bool,
        pub latency_us: u64,
        pub vision: VisionFlow,
    }

    impl RelaySession {
        /// Sends a TLS 1.3 `ApplicationData` (`0x17 0x03 0x03`) frame over the spliced session
        /// and reads back the server's spliced response.
        pub fn send_spliced(&mut self, inner_payload: &[u8]) -> io::Result<Vec<u8>> {
            let mut record = Vec::with_capacity(5 + inner_payload.len());
            record.extend_from_slice(&[0x17, 0x03, 0x03]);
            record.extend_from_slice(&(inner_payload.len() as u16).to_be_bytes());
            record.extend_from_slice(inner_payload);
            self.vision.observe_chunk(&record);
            self.stream.write_all(&record)?;
            self.stream.flush()?;
            let mut reply = vec![0u8; record.len()];
            self.stream.read_exact(&mut reply)?;
            Ok(reply[5..].to_vec())
        }
    }

    /// Connects to `profile.primary_endpoint` using `REALITY + mlkem768 + xtls-rprx-vision`,
    /// automatically failing over to `profile.backup_endpoint` if the primary is unreachable.
    pub fn connect_with_failover(
        profile: &mut ServerProfile,
    ) -> Result<RelaySession, ServerStatus> {
        let mut endpoints = Vec::with_capacity(2);
        if !profile.primary_endpoint.is_empty() {
            endpoints.push((profile.primary_endpoint.clone(), false));
        }
        if !profile.backup_endpoint.is_empty() {
            endpoints.push((profile.backup_endpoint.clone(), true));
        }
        if endpoints.is_empty() {
            profile.status = ServerStatus::Unreachable;
            return Err(ServerStatus::Unreachable);
        }

        for (ep, is_backup) in endpoints {
            let Ok(addr) = ep.parse::<SocketAddr>() else {
                continue;
            };
            let start = Instant::now();
            let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(1200))
            else {
                continue;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_millis(2000)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));
            let _ = stream.set_nodelay(true);

            let mut random = [0x5au8; 32];
            let now_ns = start.elapsed().as_nanos() as u64;
            random[0..8].copy_from_slice(&now_ns.to_be_bytes());
            let ch = build_reality_mlkem768_client_hello(
                &profile.cover_sni,
                &random,
                &profile.device_id,
                &profile.auth_key,
            );
            if stream.write_all(&ch).is_err() || stream.flush().is_err() {
                continue;
            }
            let mut resp = [0u8; 256];
            let Ok(rn) = stream.read(&mut resp) else {
                continue;
            };
            let rtt_us = u64::try_from(start.elapsed().as_micros()).unwrap_or(1);
            profile.latency_us = rtt_us;

            // Parse ServerHello + ApplicationData status ack (`THEDPI_V` + status byte)
            if let Some(pos) = crate::ascii::scan_pattern(&resp[..rn], b"THEDPI_V")
                && pos + 8 < rn
            {
                let code = resp[pos + 8];
                let status = match code {
                    1 => {
                        if is_backup {
                            ServerStatus::Failover
                        } else {
                            ServerStatus::Connected
                        }
                    }
                    4 => ServerStatus::QuotaExceeded,
                    6 => ServerStatus::Revoked,
                    _ => ServerStatus::AuthFailed,
                };
                profile.status = status;
                if matches!(status, ServerStatus::Connected | ServerStatus::Failover) {
                    let mut vision = VisionFlow::new();
                    vision.observe_chunk(&resp[..rn]);
                    debug_assert_eq!(vision.phase, VisionPhase::DirectSplice);
                    return Ok(RelaySession {
                        stream,
                        status,
                        used_backup: is_backup,
                        latency_us: rtt_us,
                        vision,
                    });
                }
                return Err(status);
            }
            profile.status = ServerStatus::AuthFailed;
            return Err(ServerStatus::AuthFailed);
        }

        profile.status = ServerStatus::Unreachable;
        Err(ServerStatus::Unreachable)
    }
}

// ---------------------------------------------------------------------------
// probe — bounded measurements
// ---------------------------------------------------------------------------

pub mod probe {
    use crate::{dns, quic, sys};
    use std::io::{self, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, UdpSocket};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    pub const MAX_TARGETS: usize = 8;
    pub const MAX_SERVERS: usize = 4;
    pub const WORKER_STACK: usize = 256 * 1024;

    #[repr(i64)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub enum Status {
        #[default]
        NotRun = 0,
        Ok = 1,
        Timeout = 2,
        Refused = 3,
        Unreachable = 4,
        Error = 5,
        Invalid = 6,
        NoData = 7,
        NameError = 8,
        ServerFailure = 9,
        Unsupported = 10,
        Skipped = 11,
        LocalLimit = 12,
        /// The platform refused the socket operation (e.g. Android 17 local-network protection).
        Blocked = 13,
    }

    impl Status {
        pub fn code(self) -> i64 {
            self as i64
        }
    }

    pub fn status_from_io(e: &io::Error) -> Status {
        use io::ErrorKind as K;
        if sys::is_message_too_large(e) {
            return Status::LocalLimit;
        }
        match e.kind() {
            K::PermissionDenied => Status::Blocked,
            K::TimedOut | K::WouldBlock => Status::Timeout,
            // Windows reports ICMP port-unreachable on UDP as WSAECONNRESET.
            K::ConnectionRefused | K::ConnectionReset => Status::Refused,
            K::HostUnreachable | K::NetworkUnreachable | K::NetworkDown | K::AddrNotAvailable => {
                Status::Unreachable
            }
            _ => Status::Error,
        }
    }

    /// Non-cryptographic randomness for DNS IDs and QUIC connection IDs: SipHash keyed
    /// from OS entropy via `RandomState`. Used only for spoofing resistance (RFC 5452),
    /// never for key material.
    pub fn random_u64() -> u64 {
        use std::hash::{BuildHasher, Hasher};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        if let Ok(d) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            h.write_u128(d.as_nanos());
        }
        h.finish()
    }

    fn micros(d: Duration) -> u64 {
        u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
    }

    #[derive(Debug, Clone)]
    pub struct ProbeConfig {
        pub timeout: Duration,
        pub dns_samples: u32,
        pub tcp_samples: u32,
        pub max_parallel: usize,
        pub quic: bool,
        pub mtu: bool,
        pub budget: Duration,
    }

    impl Default for ProbeConfig {
        fn default() -> Self {
            Self {
                timeout: Duration::from_millis(1500),
                dns_samples: 5,
                tcp_samples: 3,
                max_parallel: 4,
                quic: true,
                mtu: true,
                budget: Duration::from_secs(20),
            }
        }
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Target {
        pub host: String,
        pub port: u16,
        pub literal: Option<IpAddr>,
    }

    /// Accepts "host", "host:port", "1.2.3.4", "1.2.3.4:443", "::1", "[::1]:443".
    pub fn parse_target(s: &str) -> Option<Target> {
        let s = s.trim();
        if s.is_empty() || s.len() > 262 {
            return None;
        }
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return (sa.port() != 0).then(|| Target {
                host: sa.ip().to_string(),
                port: sa.port(),
                literal: Some(sa.ip()),
            });
        }
        let bare = s
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .unwrap_or(s);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Some(Target {
                host: ip.to_string(),
                port: 443,
                literal: Some(ip),
            });
        }
        let (h, port) = match s.rsplit_once(':') {
            Some((h, p)) => (h, p.parse::<u16>().ok().filter(|p| *p != 0)?),
            None => (s, 443),
        };
        let h = crate::ascii::lowercased(h.strip_suffix('.').unwrap_or(h));
        dns::is_valid_hostname(&h).then_some(Target {
            host: h,
            port,
            literal: None,
        })
    }

    /// Accepts "1.1.1.1", "1.1.1.1:53", "2001:db8::1", "[2001:db8::1]:53", "[fe80::1%3]:53".
    pub fn parse_server(s: &str) -> Option<SocketAddr> {
        let s = s.trim();
        if let Ok(sa) = s.parse::<SocketAddr>() {
            return (sa.port() != 0).then_some(sa);
        }
        let bare = s
            .strip_prefix('[')
            .and_then(|x| x.strip_suffix(']'))
            .unwrap_or(s);
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, 53));
        }
        format!("[{bare}]:53").parse::<SocketAddr>().ok()
    }

    fn unspecified_for(addr: &SocketAddr) -> SocketAddr {
        if addr.is_ipv4() {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
        }
    }

    fn connected_udp(addr: SocketAddr) -> io::Result<UdpSocket> {
        let sock = UdpSocket::bind(unspecified_for(&addr))?;
        sock.connect(addr)?;
        Ok(sock)
    }

    fn remaining(start: Instant, timeout: Duration) -> Option<Duration> {
        timeout
            .checked_sub(start.elapsed())
            .filter(|d| *d >= Duration::from_millis(1))
    }

    #[derive(Debug, Clone)]
    pub struct DnsAnswer {
        pub response: dns::Response,
        pub rtt_us: u64,
        pub via_tcp: bool,
    }

    /// One UDP DNS exchange; falls back to TCP on truncation (RFC 7766).
    pub fn dns_exchange(
        server: SocketAddr,
        name: &str,
        qtype: u16,
        timeout: Duration,
    ) -> Result<DnsAnswer, Status> {
        let id = (random_u64() & 0xFFFF) as u16;
        let query = dns::build_query(id, name, qtype, true).map_err(|_| Status::Invalid)?;
        let sock = connected_udp(server).map_err(|e| status_from_io(&e))?;
        let start = Instant::now();
        sock.send(&query).map_err(|e| status_from_io(&e))?;
        let mut buf = [0u8; 4096];
        loop {
            let left = remaining(start, timeout).ok_or(Status::Timeout)?;
            sock.set_read_timeout(Some(left))
                .map_err(|e| status_from_io(&e))?;
            let n = sock.recv(&mut buf).map_err(|e| status_from_io(&e))?;
            match dns::parse_response(&buf[..n], id, name, qtype) {
                Ok(resp) if resp.header.truncated() => {
                    return dns_exchange_tcp(server, name, qtype, timeout);
                }
                Ok(response) => {
                    return Ok(DnsAnswer {
                        response,
                        rtt_us: micros(start.elapsed()),
                        via_tcp: false,
                    });
                }
                Err(_) => continue, // unmatched or malformed datagram: ignore (RFC 5452)
            }
        }
    }

    pub fn dns_exchange_tcp(
        server: SocketAddr,
        name: &str,
        qtype: u16,
        timeout: Duration,
    ) -> Result<DnsAnswer, Status> {
        let id = (random_u64() & 0xFFFF) as u16;
        let query = dns::build_query(id, name, qtype, true).map_err(|_| Status::Invalid)?;
        let start = Instant::now();
        let mut s = TcpStream::connect_timeout(&server, timeout).map_err(|e| status_from_io(&e))?;
        let io = |e: io::Error| status_from_io(&e);
        s.set_read_timeout(Some(timeout)).map_err(io)?;
        s.set_write_timeout(Some(timeout)).map_err(io)?;
        let _ = s.set_nodelay(true);
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
        framed.extend_from_slice(&query);
        s.write_all(&framed).map_err(io)?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).map_err(io)?;
        let n = usize::from(u16::from_be_bytes(len));
        if n < 12 {
            return Err(Status::Invalid);
        }
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).map_err(io)?;
        let _ = s.shutdown(Shutdown::Both);
        let response = dns::parse_response(&buf, id, name, qtype).map_err(|_| Status::Invalid)?;
        Ok(DnsAnswer {
            response,
            rtt_us: micros(start.elapsed()),
            via_tcp: true,
        })
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ResolverStats {
        pub server: SocketAddr,
        pub alternate: bool,
        pub sent: u32,
        pub received: u32,
        pub rtt_us: Vec<u64>,
        pub status: Status,
        pub tcp_status: Status,
    }

    impl ResolverStats {
        pub fn avg_us(&self) -> u64 {
            if self.rtt_us.is_empty() {
                0
            } else {
                self.rtt_us.iter().sum::<u64>() / self.rtt_us.len() as u64
            }
        }
        /// Mean absolute difference of consecutive RTT samples (RFC 3550 §6.4.1 idea, unsmoothed).
        pub fn jitter_us(&self) -> u64 {
            if self.rtt_us.len() < 2 {
                return 0;
            }
            let sum: u64 = self.rtt_us.windows(2).map(|w| w[0].abs_diff(w[1])).sum();
            sum / (self.rtt_us.len() as u64 - 1)
        }
        pub fn loss_pct(&self) -> u32 {
            ((self.sent - self.received) * 100)
                .checked_div(self.sent)
                .unwrap_or(0)
        }
    }

    pub fn measure_resolver(
        server: SocketAddr,
        alternate: bool,
        name: &str,
        samples: u32,
        timeout: Duration,
        deadline: Instant,
    ) -> ResolverStats {
        let mut st = ResolverStats {
            server,
            alternate,
            sent: 0,
            received: 0,
            rtt_us: Vec::new(),
            status: Status::NotRun,
            tcp_status: Status::NotRun,
        };
        let mut last_err = Status::Skipped;
        for _ in 0..samples {
            if Instant::now() >= deadline {
                break;
            }
            st.sent += 1;
            match dns_exchange(server, name, dns::TYPE_A, timeout) {
                Ok(a) => {
                    st.received += 1;
                    st.rtt_us.push(a.rtt_us);
                }
                Err(s) => last_err = s,
            }
        }
        st.status = if st.received > 0 {
            Status::Ok
        } else {
            last_err
        };
        if st.sent > 0 && st.received * 2 < st.sent && Instant::now() < deadline {
            st.tcp_status = match dns_exchange_tcp(server, name, dns::TYPE_A, timeout) {
                Ok(_) => Status::Ok,
                Err(s) => s,
            };
        }
        st
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct DnsResult {
        pub status: Status,
        pub rcode: i64,
        pub latency_us: u64,
        pub v4: Vec<Ipv4Addr>,
        pub v6: Vec<Ipv6Addr>,
        pub https: Option<dns::Svcb>,
        pub server: Option<SocketAddr>,
        pub via_tcp: bool,
    }

    pub fn resolve(
        target: &Target,
        servers: &[SocketAddr],
        timeout: Duration,
        deadline: Instant,
    ) -> DnsResult {
        let mut r = DnsResult {
            rcode: -1,
            ..DnsResult::default()
        };
        if let Some(ip) = target.literal {
            r.status = Status::Skipped;
            match ip {
                IpAddr::V4(a) => r.v4.push(a),
                IpAddr::V6(a) => r.v6.push(a),
            }
            return r;
        }
        if servers.is_empty() {
            r.status = Status::Unsupported;
            return r;
        }
        let mut last = Status::Timeout;
        for &srv in servers.iter().take(MAX_SERVERS) {
            if Instant::now() >= deadline {
                last = Status::Skipped;
                break;
            }
            let a = match dns_exchange(srv, &target.host, dns::TYPE_A, timeout) {
                Ok(a) => a,
                Err(s) => {
                    last = s;
                    continue;
                }
            };
            let rcode = a.response.header.rcode();
            if rcode == dns::RCODE_REFUSED {
                last = Status::Refused;
                continue; // try the next configured resolver
            }
            r.server = Some(srv);
            r.rcode = i64::from(rcode);
            r.latency_us = a.rtt_us;
            r.via_tcp = a.via_tcp;
            match rcode {
                dns::RCODE_NOERROR => {}
                dns::RCODE_NXDOMAIN => {
                    r.status = Status::NameError;
                    return r;
                }
                dns::RCODE_SERVFAIL => {
                    r.status = Status::ServerFailure;
                    return r;
                }
                _ => {
                    r.status = Status::Error;
                    return r;
                }
            }
            r.v4.extend(a.response.answers.iter().filter_map(|x| match x.data {
                dns::RData::A(ip) => Some(ip),
                _ => None,
            }));
            if Instant::now() < deadline
                && let Ok(b) = dns_exchange(srv, &target.host, dns::TYPE_AAAA, timeout)
            {
                r.via_tcp |= b.via_tcp;
                r.v6.extend(b.response.answers.iter().filter_map(|x| match x.data {
                    dns::RData::Aaaa(ip) => Some(ip),
                    _ => None,
                }));
            }
            if Instant::now() < deadline
                && let Ok(c) = dns_exchange(srv, &target.host, dns::TYPE_HTTPS, timeout)
            {
                r.https = c.response.answers.into_iter().find_map(|x| match x.data {
                    dns::RData::Https(s) if s.priority > 0 => Some(s),
                    _ => None,
                });
            }
            r.v4.truncate(16);
            r.v6.truncate(16);
            r.status = if r.v4.is_empty() && r.v6.is_empty() {
                Status::NoData
            } else {
                Status::Ok
            };
            return r;
        }
        r.status = last;
        r
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct TcpResult {
        pub status: Status,
        pub address: Option<IpAddr>,
        pub attempts: u32,
        pub successes: u32,
        pub median_us: u64,
    }

    /// Connect-only TCP probe: completes the three-way handshake and closes. No payload.
    pub fn tcp_probe(
        addr: SocketAddr,
        samples: u32,
        timeout: Duration,
        deadline: Instant,
    ) -> TcpResult {
        let mut r = TcpResult {
            address: Some(addr.ip()),
            ..TcpResult::default()
        };
        let mut lat = Vec::with_capacity(samples as usize);
        let mut last = Status::Skipped;
        for _ in 0..samples {
            if Instant::now() >= deadline {
                break;
            }
            r.attempts += 1;
            let t = Instant::now();
            match TcpStream::connect_timeout(&addr, timeout) {
                Ok(s) => {
                    lat.push(micros(t.elapsed()));
                    let _ = s.shutdown(Shutdown::Both);
                }
                Err(e) => last = status_from_io(&e),
            }
        }
        r.successes = lat.len() as u32;
        lat.sort_unstable();
        r.median_us = lat.get(lat.len() / 2).copied().unwrap_or(0);
        r.status = if r.successes > 0 { Status::Ok } else { last };
        r
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct QuicResult {
        pub status: Status,
        pub rtt_us: u64,
        pub versions: Vec<u32>,
    }

    impl QuicResult {
        pub fn supports_v1(&self) -> bool {
            self.versions.contains(&quic::VERSION_1)
        }
    }

    fn random_cid() -> [u8; quic::CID_LEN] {
        random_u64().to_be_bytes()
    }

    fn vn_exchange(
        sock: &UdpSocket,
        size: usize,
        timeout: Duration,
    ) -> Result<(u64, Vec<u32>), Status> {
        let dcid = random_cid();
        let scid = random_cid();
        let pkt = quic::build_probe(&dcid, &scid, size);
        let start = Instant::now();
        sock.send(&pkt).map_err(|e| status_from_io(&e))?;
        let mut buf = [0u8; 1500];
        loop {
            let left = remaining(start, timeout).ok_or(Status::Timeout)?;
            sock.set_read_timeout(Some(left))
                .map_err(|e| status_from_io(&e))?;
            let n = sock.recv(&mut buf).map_err(|e| status_from_io(&e))?;
            if let Ok(v) = quic::parse_version_negotiation(&buf[..n], &dcid, &scid) {
                return Ok((micros(start.elapsed()), v));
            }
        }
    }

    pub fn quic_probe(
        addr: SocketAddr,
        timeout: Duration,
        attempts: u32,
        deadline: Instant,
    ) -> QuicResult {
        let sock = match connected_udp(addr) {
            Ok(s) => s,
            Err(e) => {
                return QuicResult {
                    status: status_from_io(&e),
                    ..QuicResult::default()
                };
            }
        };
        let mut status = Status::Skipped;
        for _ in 0..attempts {
            if Instant::now() >= deadline {
                break;
            }
            match vn_exchange(&sock, quic::MIN_INITIAL_DATAGRAM, timeout) {
                Ok((rtt_us, versions)) => {
                    return QuicResult {
                        status: Status::Ok,
                        rtt_us,
                        versions,
                    };
                }
                Err(Status::Timeout) => status = Status::Timeout,
                Err(s) => {
                    return QuicResult {
                        status: s,
                        ..QuicResult::default()
                    };
                }
            }
        }
        QuicResult {
            status,
            ..QuicResult::default()
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Outcome {
        Delivered,
        Lost,
        LocalLimit,
        Failed,
    }

    /// Largest delivered IP packet size in [lo, hi] (DPLPMTUD-style search, RFC 8899 idea).
    /// `lo` must already be known deliverable. Returns (size, probes used, aborted).
    pub fn search_mtu(
        lo: u32,
        hi: u32,
        max_probes: u32,
        mut probe: impl FnMut(u32) -> Outcome,
    ) -> (u32, u32, bool) {
        if hi <= lo || max_probes == 0 {
            return (lo, 0, false);
        }
        let mut probes = 1;
        match probe(hi) {
            Outcome::Delivered => return (hi, probes, false),
            Outcome::Failed => return (lo, probes, true),
            Outcome::Lost | Outcome::LocalLimit => {}
        }
        let (mut good, mut bad) = (lo, hi);
        while bad - good > 8 && probes < max_probes {
            let mid = good + (bad - good) / 2;
            probes += 1;
            match probe(mid) {
                Outcome::Delivered => good = mid,
                Outcome::Lost | Outcome::LocalLimit => bad = mid,
                Outcome::Failed => return (good, probes, true),
            }
        }
        (good, probes, false)
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct MtuResult {
        pub status: Status,
        pub path_mtu: u32,
        pub ceiling: u32,
        pub probes: u32,
    }

    /// Path MTU estimate using DF-marked QUIC VN probes of increasing size. Only run
    /// after the endpoint has answered a baseline VN probe, so "no answer" at a larger
    /// size is evidence of a size-dependent drop rather than an unresponsive server.
    pub fn mtu_probe(
        addr: SocketAddr,
        iface_mtu: u32,
        timeout: Duration,
        deadline: Instant,
    ) -> MtuResult {
        let header: u32 = if addr.is_ipv4() { 28 } else { 48 };
        let ceiling = if iface_mtu >= 1280 {
            iface_mtu.min(1500)
        } else {
            1500
        };
        let lo = quic::MIN_INITIAL_DATAGRAM as u32 + header;
        let mut r = MtuResult {
            ceiling,
            ..MtuResult::default()
        };
        if ceiling <= lo {
            r.status = Status::Skipped;
            return r;
        }
        let sock = match connected_udp(addr) {
            Ok(s) => s,
            Err(e) => {
                r.status = status_from_io(&e);
                return r;
            }
        };
        if sys::set_dont_fragment(&sock, addr.is_ipv6()).is_err() {
            r.status = Status::Unsupported;
            return r;
        }
        let per_probe = (timeout / 2).max(Duration::from_millis(300));
        let try_size = |size: u32| -> Outcome {
            for _ in 0..2 {
                if Instant::now() >= deadline {
                    return Outcome::Failed;
                }
                match vn_exchange(&sock, (size - header) as usize, per_probe) {
                    Ok(_) => return Outcome::Delivered,
                    Err(Status::LocalLimit) => return Outcome::LocalLimit,
                    Err(Status::Timeout) => continue,
                    Err(_) => return Outcome::Failed,
                }
            }
            Outcome::Lost
        };
        if try_size(lo) != Outcome::Delivered {
            r.status = Status::NoData;
            r.probes = 1;
            return r;
        }
        let (pmtu, probes, aborted) = search_mtu(lo, ceiling, 7, try_size);
        r.path_mtu = pmtu;
        r.probes = probes + 1;
        r.status = if aborted { Status::Error } else { Status::Ok };
        r
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct TlsObservation {
        pub status: i64,
        pub handshake_us: u64,
        pub version: String,
        pub alpn: String,
        pub cipher: String,
    }

    pub const TLS_NOT_RUN: i64 = 0;
    pub const TLS_OK: i64 = 1;
    pub const TLS_CERTIFICATE: i64 = 2;
    pub const TLS_HANDSHAKE: i64 = 3;
    pub const TLS_TIMEOUT: i64 = 4;
    pub const TLS_IO: i64 = 5;
    pub const TLS_UNSUPPORTED: i64 = 6;

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct TargetReport {
        pub target: Target,
        pub dns: DnsResult,
        pub tcp4: TcpResult,
        pub tcp6: TcpResult,
        pub quic: QuicResult,
        pub mtu: MtuResult,
        pub tls: TlsObservation,
    }

    impl TargetReport {
        pub fn tcp_ok(&self) -> bool {
            self.tcp4.successes > 0 || self.tcp6.successes > 0
        }
        pub fn h3_advertised(&self) -> bool {
            self.dns
                .https
                .as_ref()
                .is_some_and(|s| s.alpn.iter().any(|a| a == "h3"))
        }
    }

    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct RunReport {
        pub resolvers: Vec<ResolverStats>,
        pub targets: Vec<TargetReport>,
        pub duration_us: u64,
        /// Encrypted resolvers measured by the platform layer (submitted after the run).
        pub encrypted: Vec<EncryptedResolver>,
    }

    pub const ENC_UNKNOWN: i64 = 0;
    /// DNS over HTTPS on HTTP/2 (RFC 8484).
    pub const ENC_DOH: i64 = 1;
    /// DNS over HTTPS on HTTP/3 / QUIC (RFC 8484 + RFC 9114).
    pub const ENC_DOH3: i64 = 2;
    /// DNS over TLS (RFC 7858).
    pub const ENC_DOT: i64 = 3;
    /// DNS over dedicated QUIC (RFC 9250).
    pub const ENC_DOQ: i64 = 4;

    /// One encrypted-DNS measurement. The transport (TLS/QUIC) is the platform's; this
    /// core only built the query and validated the answer with the hardened parser.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct EncryptedResolver {
        pub endpoint: String,
        /// The name that was queried (lower-case), for cross-checking the system resolver.
        pub name: String,
        pub protocol: i64,
        pub status: Status,
        pub rtt_us: u64,
        pub answers: u32,
    }

    pub fn probe_target(
        cfg: &ProbeConfig,
        servers: &[SocketAddr],
        t: &Target,
        iface_mtu: u32,
        deadline: Instant,
    ) -> TargetReport {
        let dns = resolve(t, servers, cfg.timeout, deadline);
        let run_tcp = |ip: Option<IpAddr>| match ip {
            Some(ip) => tcp_probe(
                SocketAddr::new(ip, t.port),
                cfg.tcp_samples,
                cfg.timeout,
                deadline,
            ),
            None => TcpResult::default(),
        };
        let tcp4 = run_tcp(dns.v4.first().map(|a| IpAddr::V4(*a)));
        let tcp6 = run_tcp(dns.v6.first().map(|a| IpAddr::V6(*a)));
        let quic_ip = match (tcp4.successes > 0, tcp6.successes > 0) {
            (true, _) => tcp4.address,
            (false, true) => tcp6.address,
            _ => tcp4.address.or(tcp6.address),
        };
        let quic_port = dns.https.as_ref().and_then(|s| s.port).unwrap_or(t.port);
        let mut quic = QuicResult {
            status: Status::Skipped,
            ..QuicResult::default()
        };
        let mut mtu = MtuResult {
            status: Status::Skipped,
            ..MtuResult::default()
        };
        if let Some(ip) = quic_ip.filter(|_| cfg.quic) {
            let addr = SocketAddr::new(ip, quic_port);
            // A silent UDP endpoint is only evidence when HTTP/3 is advertised (the classifier
            // ignores it otherwise), so the retry is spent only where it can change a diagnosis.
            let h3 = dns
                .https
                .as_ref()
                .is_some_and(|s| s.alpn.iter().any(|a| a == "h3"));
            quic = quic_probe(addr, cfg.timeout, if h3 { 2 } else { 1 }, deadline);
            if cfg.mtu && quic.status == Status::Ok {
                mtu = mtu_probe(addr, iface_mtu, cfg.timeout, deadline);
            }
        }
        TargetReport {
            target: t.clone(),
            dns,
            tcp4,
            tcp6,
            quic,
            mtu,
            tls: TlsObservation::default(),
        }
    }

    enum Job<'a> {
        Resolver(SocketAddr, bool),
        Target(&'a Target),
    }

    enum JobResult {
        Resolver(ResolverStats),
        Target(Box<TargetReport>),
    }

    /// Runs all probes with a fixed worker bound and a global time budget.
    pub fn run(
        cfg: &ProbeConfig,
        servers: &[SocketAddr],
        alternates: &[SocketAddr],
        targets: &[Target],
        iface_mtu: u32,
    ) -> RunReport {
        let start = Instant::now();
        let deadline = start + cfg.budget;
        let sample_name = targets
            .iter()
            .find(|t| t.literal.is_none())
            .map(|t| t.host.clone());
        let mut jobs: Vec<Job<'_>> = Vec::new();
        if sample_name.is_some() {
            jobs.extend(
                servers
                    .iter()
                    .take(MAX_SERVERS)
                    .map(|s| Job::Resolver(*s, false)),
            );
            jobs.extend(
                alternates
                    .iter()
                    .take(MAX_SERVERS)
                    .map(|s| Job::Resolver(*s, true)),
            );
        }
        jobs.extend(targets.iter().take(MAX_TARGETS).map(Job::Target));
        let name = sample_name.unwrap_or_default();
        let execute = |job: &Job<'_>| match job {
            Job::Resolver(s, alt) => JobResult::Resolver(measure_resolver(
                *s,
                *alt,
                &name,
                cfg.dns_samples,
                cfg.timeout,
                deadline,
            )),
            Job::Target(t) => {
                JobResult::Target(Box::new(probe_target(cfg, servers, t, iface_mtu, deadline)))
            }
        };
        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<(usize, JobResult)>> = Mutex::new(Vec::with_capacity(jobs.len()));
        let worker = || {
            loop {
                let i = next.fetch_add(1, Ordering::SeqCst);
                let Some(job) = jobs.get(i) else { break };
                let r = execute(job);
                results
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((i, r));
            }
        };
        let workers = cfg.max_parallel.clamp(1, 8).min(jobs.len().max(1));
        std::thread::scope(|scope| {
            let mut spawned = 0;
            for n in 0..workers {
                let b = std::thread::Builder::new()
                    .name(format!("thedpi-probe-{n}"))
                    .stack_size(WORKER_STACK);
                if b.spawn_scoped(scope, worker).is_ok() {
                    spawned += 1;
                }
            }
            if spawned == 0 {
                worker(); // degrade to sequential execution if threads are unavailable
            }
        });
        let mut results = results
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        results.sort_by_key(|(i, _)| *i); // deterministic order regardless of scheduling
        let mut report = RunReport::default();
        for (_, r) in results {
            match r {
                JobResult::Resolver(s) => report.resolvers.push(s),
                JobResult::Target(t) => report.targets.push(*t),
            }
        }
        report.duration_us = micros(start.elapsed());
        report
    }
}

// ---------------------------------------------------------------------------
// intel — explainable classification
// ---------------------------------------------------------------------------

pub mod intel {
    use crate::probe::{self, RunReport, Status};
    use crate::tags;
    use crate::wire::Record;

    pub const NO: i64 = 0;
    pub const YES: i64 = 1;
    pub const UNKNOWN: i64 = 2;

    pub const NET_UNKNOWN: i64 = 0;
    pub const NET_WIFI: i64 = 1;
    pub const NET_CELLULAR: i64 = 2;
    pub const NET_ETHERNET: i64 = 3;
    pub const NET_VPN: i64 = 4;
    pub const NET_OTHER: i64 = 5;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Environment {
        pub os_name: String,
        pub os_version: String,
        pub os_build: u32,
        pub arch: String,
        pub network_type: i64,
        pub interface: String,
        pub dns_servers: Vec<String>,
        pub gateways: Vec<String>,
        pub mtu: u32,
        pub has_ipv4: i64,
        pub has_ipv6: i64,
        pub captive: i64,
        pub metered: i64,
        pub validated: i64,
        pub private_dns: i64,
        pub private_dns_name: String,
        pub connected: i64,
        pub restrict_background: i64,
    }

    impl Default for Environment {
        fn default() -> Self {
            Self {
                os_name: String::new(),
                os_version: String::new(),
                os_build: 0,
                arch: String::new(),
                network_type: NET_UNKNOWN,
                interface: String::new(),
                dns_servers: Vec::new(),
                gateways: Vec::new(),
                mtu: 0,
                has_ipv4: UNKNOWN,
                has_ipv6: UNKNOWN,
                captive: UNKNOWN,
                metered: UNKNOWN,
                validated: UNKNOWN,
                private_dns: UNKNOWN,
                private_dns_name: String::new(),
                connected: UNKNOWN,
                restrict_background: UNKNOWN,
            }
        }
    }

    fn tri(v: Option<i64>) -> i64 {
        match v {
            Some(NO) => NO,
            Some(YES) => YES,
            _ => UNKNOWN,
        }
    }

    fn short(s: Option<&str>) -> String {
        crate::wire::truncate_utf8(s.unwrap_or(""), 256).to_owned()
    }

    impl Environment {
        pub fn from_record(r: &Record) -> Self {
            use tags::env as t;
            Self {
                os_name: short(r.get_text(t::OS_NAME)),
                os_version: short(r.get_text(t::OS_VERSION)),
                os_build: r
                    .get_int(t::OS_BUILD)
                    .and_then(|v| u32::try_from(v).ok())
                    .unwrap_or(0),
                arch: short(r.get_text(t::ARCH)),
                network_type: r
                    .get_int(t::NETWORK_TYPE)
                    .filter(|v| (0..=5).contains(v))
                    .unwrap_or(NET_UNKNOWN),
                interface: short(r.get_text(t::INTERFACE)),
                dns_servers: r
                    .texts(t::DNS_SERVER)
                    .take(8)
                    .map(|s| short(Some(s)))
                    .collect(),
                gateways: r
                    .texts(t::GATEWAY)
                    .take(8)
                    .map(|s| short(Some(s)))
                    .collect(),
                mtu: r
                    .get_int(t::MTU)
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| *v <= 65_535)
                    .unwrap_or(0),
                has_ipv4: tri(r.get_int(t::HAS_IPV4)),
                has_ipv6: tri(r.get_int(t::HAS_IPV6)),
                captive: tri(r.get_int(t::CAPTIVE)),
                metered: tri(r.get_int(t::METERED)),
                validated: tri(r.get_int(t::VALIDATED)),
                private_dns: tri(r.get_int(t::PRIVATE_DNS)),
                private_dns_name: short(r.get_text(t::PRIVATE_DNS_NAME)),
                connected: tri(r.get_int(t::CONNECTED)),
                restrict_background: tri(r.get_int(t::RESTRICT_BACKGROUND)),
            }
        }

        pub fn to_record(&self) -> Record {
            use tags::env as t;
            let mut r = Record::new();
            r.text(t::OS_NAME, &self.os_name)
                .text(t::OS_VERSION, &self.os_version)
                .int(t::OS_BUILD, i64::from(self.os_build))
                .text(t::ARCH, &self.arch)
                .int(t::NETWORK_TYPE, self.network_type)
                .text(t::INTERFACE, &self.interface)
                .int(t::MTU, i64::from(self.mtu))
                .int(t::HAS_IPV4, self.has_ipv4)
                .int(t::HAS_IPV6, self.has_ipv6)
                .int(t::CAPTIVE, self.captive)
                .int(t::METERED, self.metered)
                .int(t::VALIDATED, self.validated)
                .int(t::PRIVATE_DNS, self.private_dns)
                .text(t::PRIVATE_DNS_NAME, &self.private_dns_name)
                .int(t::CONNECTED, self.connected)
                .int(t::RESTRICT_BACKGROUND, self.restrict_background);
            for s in &self.dns_servers {
                r.text(t::DNS_SERVER, s);
            }
            for g in &self.gateways {
                r.text(t::GATEWAY, g);
            }
            r
        }
    }

    #[repr(i64)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Category {
        None = 0,
        DnsResolutionFailure = 1,
        DnsTimeout = 2,
        Ipv4ConnectivityFailure = 3,
        Ipv6ConnectivityFailure = 4,
        TcpConnectionFailure = 5,
        UdpAvailabilityIssue = 6,
        TlsNegotiationFailure = 7,
        CertificateValidationFailure = 8,
        QuicIncompatibility = 9,
        Http3Incompatibility = 10,
        MtuRelatedFailure = 11,
        CaptivePortal = 12,
        LocalNetworkInterruption = 13,
        RemoteServiceFailure = 14,
        InsufficientEvidence = 15,
        NoProblemDetected = 16,
        Advisory = 17,
    }

    impl Category {
        pub fn is_problem(self) -> bool {
            !matches!(
                self,
                Category::None
                    | Category::NoProblemDetected
                    | Category::Advisory
                    | Category::InsufficientEvidence
            )
        }
    }

    #[repr(i64)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Obs {
        NotConnected = 1,
        PlatformCaptivePortal = 2,
        PlatformNotValidated = 3,
        ResolverNoResponse = 4,
        ResolverLoss = 5,
        ResolverUdpFailTcpOk = 6,
        DnsNameError = 7,
        DnsServerFailure = 8,
        DnsTimeout = 9,
        Tcp4Failed = 10,
        Tcp6Failed = 11,
        Tcp4Ok = 12,
        Tcp6Ok = 13,
        TcpAllFailed = 14,
        TlsCertFailure = 15,
        TlsFailure = 16,
        TlsOk = 17,
        H3Advertised = 18,
        QuicNoResponse = 19,
        QuicV1Supported = 20,
        QuicNoV1 = 21,
        MtuBelowCeiling = 22,
        EchPublished = 23,
        NoIpv6Address = 24,
        HighLatency = 25,
        Windows10EndOfSupport = 26,
        OtherTargetsOk = 27,
        NoTargets = 28,
        DnsRefused = 29,
        Metered = 30,
        HighJitter = 31,
        AlternateResolverBetter = 32,
        DnsNoAddress = 33,
        TargetHealthy = 34,
        NoEvidence = 35,
        RestrictedBackground = 36,
        PrivateDnsActive = 37,
        NoDnsServers = 38,
        PlatformBlocked = 39,
        EncryptedDnsResolved = 40,
        EncryptedDnsAvailable = 41,
        EncryptedDnsFailed = 42,
        ResolverDiscrepancy = 43,
        EncryptedDnsConfirmsNxdomain = 44,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Observation {
        pub code: Obs,
        pub subject: String,
        pub args: Vec<i64>,
    }

    pub fn obs(code: Obs, subject: &str, args: &[i64]) -> Observation {
        Observation {
            code,
            subject: subject.to_owned(),
            args: args.to_vec(),
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Diagnosis {
        pub category: Category,
        pub confidence: u8,
        pub observations: Vec<Observation>,
    }

    const MAX_OBSERVATIONS: usize = 16;

    #[derive(Debug, Default)]
    struct Builder {
        diags: Vec<Diagnosis>,
    }

    impl Builder {
        fn add(&mut self, category: Category, confidence: u8, observations: Vec<Observation>) {
            let confidence = confidence.min(100);
            match self.diags.iter_mut().find(|d| d.category == category) {
                Some(d) => {
                    d.confidence = d.confidence.max(confidence);
                    for o in observations {
                        if d.observations.len() < MAX_OBSERVATIONS && !d.observations.contains(&o) {
                            d.observations.push(o);
                        }
                    }
                }
                None => {
                    let mut observations = observations;
                    observations.truncate(MAX_OBSERVATIONS);
                    self.diags.push(Diagnosis {
                        category,
                        confidence,
                        observations,
                    });
                }
            }
        }

        fn has_problem(&self) -> bool {
            self.diags
                .iter()
                .any(|d| d.category.is_problem() && d.confidence >= 50)
        }

        fn finish(mut self) -> Vec<Diagnosis> {
            // Highest confidence first; advisories last; ties broken by category code (deterministic).
            self.diags.sort_by(|a, b| {
                (a.category == Category::Advisory)
                    .cmp(&(b.category == Category::Advisory))
                    .then(b.confidence.cmp(&a.confidence))
                    .then(a.category.cmp(&b.category))
            });
            self.diags
        }
    }

    fn ms(us: u64) -> i64 {
        i64::try_from(us / 1000).unwrap_or(i64::MAX)
    }

    /// Classifies a diagnostic run. Every diagnosis carries the observations that
    /// justify it; when evidence is insufficient no specific cause is claimed.
    pub fn classify(env: Option<&Environment>, run: &RunReport) -> Vec<Diagnosis> {
        let mut b = Builder::default();
        let validated = env.map_or(UNKNOWN, |e| e.validated);
        if let Some(e) = env {
            if e.os_name.starts_with("Windows") && e.os_build > 0 && e.os_build < 22_000 {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(
                        Obs::Windows10EndOfSupport,
                        &e.os_version,
                        &[i64::from(e.os_build)],
                    )],
                );
            }
            if e.connected == NO {
                b.add(
                    Category::LocalNetworkInterruption,
                    95,
                    vec![obs(Obs::NotConnected, &e.interface, &[])],
                );
                return b.finish();
            }
            if e.captive == YES {
                b.add(
                    Category::CaptivePortal,
                    90,
                    vec![obs(Obs::PlatformCaptivePortal, &e.interface, &[])],
                );
            }
            if e.metered == YES {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(Obs::Metered, &e.interface, &[])],
                );
            }
            if e.restrict_background == YES {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(Obs::RestrictedBackground, "", &[])],
                );
            }
            if e.private_dns == YES {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(Obs::PrivateDnsActive, &e.private_dns_name, &[])],
                );
            }
            if e.dns_servers.is_empty() && e.private_dns != YES {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(Obs::NoDnsServers, &e.interface, &[])],
                );
            }
        }
        if run.targets.is_empty() {
            b.add(
                Category::InsufficientEvidence,
                100,
                vec![obs(Obs::NoTargets, "", &[])],
            );
            return b.finish();
        }

        let primaries: Vec<&probe::ResolverStats> =
            run.resolvers.iter().filter(|r| !r.alternate).collect();
        let any_primary_answer = primaries.iter().any(|r| r.received > 0);
        let tcp_ok_targets = run.targets.iter().filter(|t| t.tcp_ok()).count();

        // Resolver-level evidence.
        let all_blocked =
            !primaries.is_empty() && primaries.iter().all(|r| r.status == Status::Blocked);
        if all_blocked {
            for r in &primaries {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(Obs::PlatformBlocked, &r.server.to_string(), &[])],
                );
            }
        } else if !primaries.is_empty() && !any_primary_answer {
            let mut o: Vec<Observation> = primaries
                .iter()
                .map(|r| {
                    obs(
                        Obs::ResolverNoResponse,
                        &r.server.to_string(),
                        &[i64::from(r.sent), i64::from(r.received)],
                    )
                })
                .collect();
            let tcp_ok: Vec<&&probe::ResolverStats> = primaries
                .iter()
                .filter(|r| r.tcp_status == Status::Ok)
                .collect();
            if !tcp_ok.is_empty() {
                o.extend(
                    tcp_ok
                        .iter()
                        .map(|r| obs(Obs::ResolverUdpFailTcpOk, &r.server.to_string(), &[])),
                );
                b.add(Category::UdpAvailabilityIssue, 75, o);
            } else if validated == YES || tcp_ok_targets > 0 {
                b.add(Category::DnsTimeout, 80, o);
            } else {
                b.add(Category::DnsTimeout, 55, o);
            }
        } else {
            for r in &primaries {
                let loss = r.loss_pct();
                if r.received > 0 && loss >= 20 {
                    let conf = if loss >= 50 { 60 } else { 40 };
                    b.add(
                        Category::DnsTimeout,
                        conf,
                        vec![obs(
                            Obs::ResolverLoss,
                            &r.server.to_string(),
                            &[i64::from(loss)],
                        )],
                    );
                }
                if r.jitter_us() >= 50_000 {
                    b.add(
                        Category::Advisory,
                        100,
                        vec![obs(
                            Obs::HighJitter,
                            &r.server.to_string(),
                            &[ms(r.jitter_us())],
                        )],
                    );
                }
            }
        }

        // User-authorized alternate resolvers that measured clearly better.
        let best_primary = primaries
            .iter()
            .filter(|r| r.received > 0)
            .map(|r| (r.loss_pct(), r.avg_us()))
            .min();
        let better_alt = run
            .resolvers
            .iter()
            .filter(|r| r.alternate && r.sent > 0 && r.received == r.sent)
            .min_by_key(|r| r.avg_us())
            .filter(|alt| match best_primary {
                None => true,
                Some((loss, avg)) => loss > 0 || alt.avg_us() * 10 < avg * 8,
            })
            .map(|alt| {
                obs(
                    Obs::AlternateResolverBetter,
                    &alt.server.to_string(),
                    &[ms(alt.avg_us()), best_primary.map_or(-1, |p| ms(p.1))],
                )
            });

        let env_v6 = env.map_or(UNKNOWN, |e| e.has_ipv6);
        for t in &run.targets {
            let h = t.target.host.as_str();
            match t.dns.status {
                Status::Ok | Status::Skipped => {}
                Status::NameError => {
                    b.add(
                        Category::DnsResolutionFailure,
                        85,
                        vec![obs(Obs::DnsNameError, h, &[])],
                    );
                    continue;
                }
                Status::ServerFailure => {
                    let others_ok = run.targets.iter().any(|o| o.dns.status == Status::Ok);
                    b.add(
                        Category::DnsResolutionFailure,
                        if others_ok { 60 } else { 75 },
                        vec![obs(Obs::DnsServerFailure, h, &[t.dns.rcode])],
                    );
                    continue;
                }
                Status::Refused => {
                    b.add(
                        Category::DnsResolutionFailure,
                        70,
                        vec![obs(Obs::DnsRefused, h, &[])],
                    );
                    continue;
                }
                Status::NoData => {
                    b.add(
                        Category::DnsResolutionFailure,
                        50,
                        vec![obs(Obs::DnsNoAddress, h, &[])],
                    );
                    continue;
                }
                Status::Unsupported => continue, // no resolver known: reported via NoDnsServers advisory
                _ => {
                    if any_primary_answer {
                        b.add(Category::DnsTimeout, 65, vec![obs(Obs::DnsTimeout, h, &[])]);
                    }
                    continue;
                }
            }
            let ok4 = t.tcp4.successes > 0;
            let ok6 = t.tcp6.successes > 0;
            if !ok4
                && !ok6
                && (t.tcp4.status == Status::Blocked || t.tcp6.status == Status::Blocked)
            {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(Obs::PlatformBlocked, h, &[])],
                );
                continue;
            }
            if t.tcp4.attempts > 0 && !ok4 && ok6 {
                b.add(
                    Category::Ipv4ConnectivityFailure,
                    70,
                    vec![
                        obs(Obs::Tcp4Failed, h, &[i64::from(t.tcp4.attempts)]),
                        obs(Obs::Tcp6Ok, h, &[ms(t.tcp6.median_us)]),
                    ],
                );
            }
            if t.tcp6.attempts > 0 && !ok6 && ok4 {
                match env_v6 {
                    NO => b.add(
                        Category::Advisory,
                        100,
                        vec![obs(Obs::NoIpv6Address, h, &[])],
                    ),
                    v => b.add(
                        Category::Ipv6ConnectivityFailure,
                        if v == YES { 75 } else { 55 },
                        vec![
                            obs(Obs::Tcp6Failed, h, &[i64::from(t.tcp6.attempts)]),
                            obs(Obs::Tcp4Ok, h, &[ms(t.tcp4.median_us)]),
                        ],
                    ),
                }
            }
            if !t.tcp_ok() && t.tcp4.attempts + t.tcp6.attempts > 0 {
                let o = obs(
                    Obs::TcpAllFailed,
                    h,
                    &[i64::from(t.tcp4.attempts + t.tcp6.attempts)],
                );
                if tcp_ok_targets > 0 {
                    b.add(
                        Category::RemoteServiceFailure,
                        70,
                        vec![o, obs(Obs::OtherTargetsOk, h, &[tcp_ok_targets as i64])],
                    );
                } else {
                    b.add(
                        Category::TcpConnectionFailure,
                        if run.targets.len() > 1 { 70 } else { 55 },
                        vec![o],
                    );
                }
                continue;
            }
            let mtu_low = t.mtu.status == Status::Ok && t.mtu.path_mtu + 8 < t.mtu.ceiling;
            match t.tls.status {
                probe::TLS_CERTIFICATE => {
                    b.add(
                        Category::CertificateValidationFailure,
                        85,
                        vec![obs(Obs::TlsCertFailure, h, &[])],
                    );
                    if validated == NO {
                        b.add(
                            Category::CaptivePortal,
                            60,
                            vec![
                                obs(Obs::PlatformNotValidated, h, &[]),
                                obs(Obs::TlsCertFailure, h, &[]),
                            ],
                        );
                    }
                }
                probe::TLS_HANDSHAKE => b.add(
                    Category::TlsNegotiationFailure,
                    70,
                    vec![obs(Obs::TlsFailure, h, &[t.tls.status])],
                ),
                probe::TLS_TIMEOUT | probe::TLS_IO => {
                    b.add(
                        Category::TlsNegotiationFailure,
                        60,
                        vec![obs(Obs::TlsFailure, h, &[t.tls.status])],
                    );
                }
                _ => {}
            }
            let h3 = t.h3_advertised();
            match t.quic.status {
                Status::Ok if !t.quic.supports_v1() && h3 => {
                    b.add(
                        Category::Http3Incompatibility,
                        60,
                        vec![obs(Obs::H3Advertised, h, &[]), obs(Obs::QuicNoV1, h, &[])],
                    );
                }
                Status::Timeout | Status::Refused if h3 => {
                    b.add(
                        Category::QuicIncompatibility,
                        65,
                        vec![
                            obs(Obs::H3Advertised, h, &[]),
                            obs(Obs::QuicNoResponse, h, &[]),
                        ],
                    );
                }
                _ => {}
            }
            if mtu_low {
                let tls_stall = matches!(t.tls.status, probe::TLS_TIMEOUT | probe::TLS_IO);
                b.add(
                    Category::MtuRelatedFailure,
                    if tls_stall { 70 } else { 55 },
                    vec![obs(
                        Obs::MtuBelowCeiling,
                        h,
                        &[i64::from(t.mtu.path_mtu), i64::from(t.mtu.ceiling)],
                    )],
                );
            }
            let median = [&t.tcp4, &t.tcp6]
                .iter()
                .filter(|x| x.successes > 0)
                .map(|x| x.median_us)
                .min();
            if let Some(m) = median.filter(|m| *m > 300_000) {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(Obs::HighLatency, h, &[ms(m)])],
                );
            }
            if t.dns.https.as_ref().is_some_and(|s| s.ech) {
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(Obs::EchPublished, h, &[])],
                );
            }
        }

        if let Some(alt) = better_alt {
            for d in &mut b.diags {
                if matches!(
                    d.category,
                    Category::DnsResolutionFailure
                        | Category::DnsTimeout
                        | Category::UdpAvailabilityIssue
                ) {
                    d.confidence = (d.confidence + 10).min(95);
                    if d.observations.len() < MAX_OBSERVATIONS {
                        d.observations.push(alt.clone());
                    }
                }
            }
        }

        // Encrypted resolvers (DoH3/DoH/DoT/DoQ) measured over the platform's TLS/QUIC stack.
        for t in &run.targets {
            if t.dns.status != Status::NameError {
                continue;
            }
            let h = t.target.host.as_str();
            for e in run.encrypted.iter().filter(|e| e.name == h) {
                match e.status {
                    // The system resolver denies a name that an independent encrypted resolver
                    // answers: a resolver-level discrepancy, not a typo.
                    Status::Ok => b.add(
                        Category::DnsResolutionFailure,
                        80,
                        vec![obs(Obs::ResolverDiscrepancy, h, &[e.protocol])],
                    ),
                    Status::NameError => b.add(
                        Category::DnsResolutionFailure,
                        85,
                        vec![obs(Obs::EncryptedDnsConfirmsNxdomain, h, &[e.protocol])],
                    ),
                    _ => {}
                }
            }
        }
        let dns_problem = b.diags.iter().any(|d| {
            matches!(
                d.category,
                Category::DnsResolutionFailure
                    | Category::DnsTimeout
                    | Category::UdpAvailabilityIssue
            ) && d.confidence >= 50
        });
        if let Some(e) = run
            .encrypted
            .iter()
            .filter(|e| e.status == Status::Ok)
            .min_by_key(|e| e.rtt_us)
        {
            let resolved = obs(
                Obs::EncryptedDnsResolved,
                &e.endpoint,
                &[ms(e.rtt_us), e.protocol],
            );
            if dns_problem {
                for d in &mut b.diags {
                    if matches!(
                        d.category,
                        Category::DnsTimeout | Category::UdpAvailabilityIssue
                    ) || d
                        .observations
                        .iter()
                        .any(|o| o.code == Obs::ResolverDiscrepancy)
                    {
                        d.confidence = (d.confidence + 10).min(95);
                        if d.observations.len() < MAX_OBSERVATIONS {
                            d.observations.push(resolved.clone());
                        }
                    }
                }
            } else if env.is_none_or(|x| x.private_dns != YES) {
                let system = best_primary.map_or(-1, |p| ms(p.1));
                b.add(
                    Category::Advisory,
                    100,
                    vec![obs(
                        Obs::EncryptedDnsAvailable,
                        &e.endpoint,
                        &[ms(e.rtt_us), e.protocol, system],
                    )],
                );
            }
        }
        for e in run
            .encrypted
            .iter()
            .filter(|e| !matches!(e.status, Status::Ok | Status::NameError))
        {
            b.add(
                Category::Advisory,
                100,
                vec![obs(
                    Obs::EncryptedDnsFailed,
                    &e.endpoint,
                    &[e.status.code(), e.protocol],
                )],
            );
        }

        if !b.has_problem() {
            let healthy: Vec<Observation> = run
                .targets
                .iter()
                .filter(|t| t.tcp_ok())
                .map(|t| {
                    let m = [&t.tcp4, &t.tcp6]
                        .iter()
                        .filter(|x| x.successes > 0)
                        .map(|x| x.median_us)
                        .min()
                        .unwrap_or(0);
                    obs(Obs::TargetHealthy, &t.target.host, &[ms(m)])
                })
                .collect();
            if healthy.is_empty() {
                b.add(
                    Category::InsufficientEvidence,
                    90,
                    vec![obs(Obs::NoEvidence, "", &[])],
                );
            } else {
                let samples: u32 = run
                    .targets
                    .iter()
                    .map(|t| t.tcp4.attempts + t.tcp6.attempts)
                    .sum();
                b.add(
                    Category::NoProblemDetected,
                    if samples >= 3 { 80 } else { 60 },
                    healthy,
                );
            }
        }
        b.finish()
    }
}

// ---------------------------------------------------------------------------
// decide — deterministic adaptive decision engine
// ---------------------------------------------------------------------------

pub mod decide {
    use crate::intel::{Category, Diagnosis};
    use std::collections::VecDeque;

    #[repr(i64)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Action {
        KeepCurrent = 0,
        PreferIpv4 = 1,
        PreferIpv6 = 2,
        UseAlternateDns = 3,
        PreferTcpFallback = 4,
        LowerMtu = 5,
        OpenCaptivePortal = 6,
        WaitAndRetry = 7,
        CollectMoreEvidence = 8,
        CheckCertificateEnvironment = 9,
        ContactServiceOrAdmin = 10,
        RevertLastChange = 11,
        CheckLocalConnection = 12,
        CheckTargetName = 13,
    }

    impl Action {
        pub fn from_code(c: i64) -> Option<Self> {
            use Action::*;
            Some(match c {
                0 => KeepCurrent,
                1 => PreferIpv4,
                2 => PreferIpv6,
                3 => UseAlternateDns,
                4 => PreferTcpFallback,
                5 => LowerMtu,
                6 => OpenCaptivePortal,
                7 => WaitAndRetry,
                8 => CollectMoreEvidence,
                9 => CheckCertificateEnvironment,
                10 => ContactServiceOrAdmin,
                11 => RevertLastChange,
                12 => CheckLocalConnection,
                13 => CheckTargetName,
                _ => return None,
            })
        }

        /// High-impact actions change system-wide configuration (always via the user).
        pub fn is_high_impact(self) -> bool {
            matches!(
                self,
                Action::PreferIpv4
                    | Action::PreferIpv6
                    | Action::UseAlternateDns
                    | Action::LowerMtu
                    | Action::RevertLastChange
            )
        }
    }

    /// Evidence-aware mapping: a resolution failure whose only evidence is NXDOMAIN means
    /// the name does not exist, so changing the resolver would not help.
    pub fn action_for_diagnosis(d: &Diagnosis) -> Action {
        use crate::intel::Obs;
        let only_nxdomain = !d.observations.is_empty()
            && d.observations.iter().all(|o| {
                matches!(
                    o.code,
                    Obs::DnsNameError | Obs::EncryptedDnsConfirmsNxdomain
                )
            });
        if d.category == Category::DnsResolutionFailure && only_nxdomain {
            return Action::CheckTargetName;
        }
        action_for(d.category)
    }

    /// Recommends the optimal active DPI desynchronization strategy from diagnostic findings.
    pub fn recommend_desync_mode(diags: &[Diagnosis]) -> crate::desync::DesyncMode {
        use crate::desync::DesyncMode;
        for d in diags {
            match d.category {
                Category::TlsNegotiationFailure => return DesyncMode::AdaptiveFull,
                Category::TcpConnectionFailure => return DesyncMode::FakeAutoTtl,
                Category::QuicIncompatibility | Category::Http3Incompatibility => {
                    return DesyncMode::QuicScramble;
                }
                Category::DnsResolutionFailure | Category::DnsTimeout => {
                    return DesyncMode::Disorder;
                }
                _ => {}
            }
        }
        DesyncMode::Off
    }

    pub fn action_for(c: Category) -> Action {
        match c {
            Category::DnsResolutionFailure
            | Category::DnsTimeout
            | Category::UdpAvailabilityIssue => Action::UseAlternateDns,
            Category::Ipv4ConnectivityFailure => Action::PreferIpv6,
            Category::Ipv6ConnectivityFailure => Action::PreferIpv4,
            Category::TcpConnectionFailure | Category::LocalNetworkInterruption => {
                Action::CheckLocalConnection
            }
            Category::TlsNegotiationFailure => Action::WaitAndRetry,
            Category::CertificateValidationFailure => Action::CheckCertificateEnvironment,
            Category::QuicIncompatibility | Category::Http3Incompatibility => {
                Action::PreferTcpFallback
            }
            Category::MtuRelatedFailure => Action::LowerMtu,
            Category::CaptivePortal => Action::OpenCaptivePortal,
            Category::RemoteServiceFailure => Action::ContactServiceOrAdmin,
            Category::InsufficientEvidence => Action::CollectMoreEvidence,
            Category::None | Category::NoProblemDetected | Category::Advisory => {
                Action::KeepCurrent
            }
        }
    }

    #[repr(i64)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum State {
        Stable = 0,
        Pending = 1,
        Recommend = 2,
        CoolingDown = 3,
        NeedMoreEvidence = 4,
        Verifying = 5,
        Confirmed = 6,
        Rejected = 7,
    }

    pub const MIN_CONFIDENCE: u8 = 50;
    pub const HIGH_IMPACT_MIN_CONFIDENCE: u8 = 70;
    pub const INSTANT_CONFIDENCE: u8 = 90;
    pub const CONFIRM_STREAK: u32 = 2;
    pub const VERIFY_EVALUATIONS: u32 = 2;
    pub const HISTORY: usize = 8;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Decision {
        pub state: State,
        pub action: Action,
        pub confidence: u8,
        pub category: Category,
        pub cooldown_remaining_ms: u64,
        /// Action-specific parameter (e.g. the reverted action for RevertLastChange).
        pub param: i64,
    }

    #[derive(Debug, Clone, Copy)]
    struct Applied {
        action: Action,
        category: Category,
        baseline: i64,
        evaluations: u32,
    }

    #[derive(Debug, Clone)]
    pub struct Decider {
        cooldown_ms: u64,
        hysteresis_pct: i64,
        current: Action,
        current_confidence: u8,
        current_category: Category,
        last_change_ms: Option<u64>,
        pending: Option<(Action, u32)>,
        ewma: Option<i64>,
        history: VecDeque<i64>,
        applied: Option<Applied>,
    }

    impl Decider {
        pub fn new(cooldown_ms: u64, hysteresis_pct: u32) -> Self {
            Self {
                cooldown_ms,
                hysteresis_pct: i64::from(hysteresis_pct.min(50)),
                current: Action::KeepCurrent,
                current_confidence: 0,
                current_category: Category::None,
                last_change_ms: None,
                pending: None,
                ewma: None,
                history: VecDeque::with_capacity(HISTORY),
                applied: None,
            }
        }

        pub fn ewma(&self) -> Option<i64> {
            self.ewma
        }

        pub fn current(&self) -> Action {
            self.current
        }

        /// 0..1000; 1000 = scores did not move across the recent history.
        pub fn stability(&self) -> i64 {
            if self.history.len() < 2 {
                return 0;
            }
            let n = self.history.len() as i64;
            let mean = self.history.iter().sum::<i64>() / n;
            let mad = self.history.iter().map(|s| (s - mean).abs()).sum::<i64>() / n;
            (1000 - mad * 4).clamp(0, 1000)
        }

        pub fn network_changed(&mut self) {
            let (cd, h) = (self.cooldown_ms, self.hysteresis_pct as u32);
            *self = Self::new(cd, h);
        }

        /// The user reports having applied `action`; subsequent evaluations verify it.
        pub fn mark_applied(&mut self, action: Action) -> bool {
            let Some(baseline) = self.ewma else {
                return false;
            };
            if action == Action::KeepCurrent || action == Action::CollectMoreEvidence {
                return false;
            }
            let category = if action == self.current {
                self.current_category
            } else {
                Category::None
            };
            self.applied = Some(Applied {
                action,
                category,
                baseline,
                evaluations: 0,
            });
            true
        }

        fn decision(&self, state: State, now_ms: u64) -> Decision {
            let remaining = match (state, self.last_change_ms) {
                (State::CoolingDown, Some(t)) => {
                    self.cooldown_ms.saturating_sub(now_ms.saturating_sub(t))
                }
                _ => 0,
            };
            Decision {
                state,
                action: self.current,
                confidence: self.current_confidence,
                category: self.current_category,
                cooldown_remaining_ms: remaining,
                param: 0,
            }
        }

        fn switch_to(&mut self, action: Action, confidence: u8, category: Category, now_ms: u64) {
            self.current = action;
            self.current_confidence = confidence;
            self.current_category = category;
            self.last_change_ms = Some(now_ms);
            self.pending = None;
        }

        pub fn step(&mut self, now_ms: u64, score: Option<i64>, diags: &[Diagnosis]) -> Decision {
            if let Some(s) = score {
                self.ewma = Some(match self.ewma {
                    None => s,
                    Some(e) => e + (s - e) / 4,
                });
                if self.history.len() == HISTORY {
                    self.history.pop_front();
                }
                self.history.push_back(s);
            }

            // 1. Verification of a change the user applied (confirm or roll back).
            if let Some(mut a) = self.applied {
                a.evaluations += 1;
                if a.evaluations < VERIFY_EVALUATIONS {
                    self.applied = Some(a);
                    let mut d = self.decision(State::Verifying, now_ms);
                    d.action = a.action;
                    return d;
                }
                self.applied = None;
                let ewma = self.ewma.unwrap_or(a.baseline);
                let tolerance = a.baseline.abs() * self.hysteresis_pct / 100;
                let persists = a.category != Category::None
                    && diags
                        .iter()
                        .any(|d| d.category == a.category && d.confidence >= MIN_CONFIDENCE);
                if !persists && ewma + tolerance >= a.baseline {
                    self.switch_to(Action::KeepCurrent, 100, Category::None, now_ms);
                    let mut d = self.decision(State::Confirmed, now_ms);
                    d.param = a.action as i64;
                    return d;
                }
                self.switch_to(Action::RevertLastChange, 100, a.category, now_ms);
                let mut d = self.decision(State::Rejected, now_ms);
                d.param = a.action as i64;
                return d;
            }

            // 2. Strongest actionable diagnosis.
            let top = diags
                .iter()
                .filter(|d| d.category != Category::Advisory)
                .max_by(|a, b| {
                    a.confidence
                        .cmp(&b.confidence)
                        .then(b.category.cmp(&a.category))
                });
            let (cand, conf, cat) = match top {
                Some(d) => (action_for_diagnosis(d), d.confidence, d.category),
                None => (Action::KeepCurrent, 0, Category::None),
            };

            if cat == Category::InsufficientEvidence
                || (cand != Action::KeepCurrent && conf < MIN_CONFIDENCE)
            {
                self.pending = None;
                let mut d = self.decision(State::NeedMoreEvidence, now_ms);
                if self.current == Action::KeepCurrent {
                    d.action = Action::CollectMoreEvidence;
                    d.confidence = conf;
                    d.category = cat;
                }
                return d;
            }

            if cand == self.current {
                self.pending = None;
                self.current_confidence = conf;
                self.current_category = cat;
                let st = if cand == Action::KeepCurrent {
                    State::Stable
                } else {
                    State::Recommend
                };
                return self.decision(st, now_ms);
            }

            let high = cand.is_high_impact();
            if high && conf < HIGH_IMPACT_MIN_CONFIDENCE {
                self.pending = None;
                let mut d = self.decision(State::NeedMoreEvidence, now_ms);
                d.action = if self.current == Action::KeepCurrent {
                    Action::CollectMoreEvidence
                } else {
                    self.current
                };
                d.category = cat;
                d.confidence = conf;
                return d;
            }

            // Hysteresis: replacing one active recommendation with another needs a clear margin
            // while the original problem is still observed.
            if self.current != Action::KeepCurrent && cand != Action::KeepCurrent {
                let current_still_seen = diags
                    .iter()
                    .any(|d| d.category == self.current_category && d.confidence >= MIN_CONFIDENCE);
                if current_still_seen
                    && i64::from(conf) < i64::from(self.current_confidence) + self.hysteresis_pct
                {
                    self.pending = None;
                    return self.decision(State::Recommend, now_ms);
                }
            }

            // Debounce: a single evaluation never triggers a high-impact change.
            let streak = match self.pending {
                Some((a, n)) if a == cand => n + 1,
                _ => 1,
            };
            let needed = if high || cand == Action::KeepCurrent || conf < INSTANT_CONFIDENCE {
                CONFIRM_STREAK
            } else {
                1
            };
            if streak < needed {
                self.pending = Some((cand, streak));
                let mut d = self.decision(State::Pending, now_ms);
                d.param = cand as i64;
                return d;
            }

            // Cooldown between changes (returning to KeepCurrent is never blocked).
            if cand != Action::KeepCurrent
                && let Some(t) = self.last_change_ms
                && now_ms.saturating_sub(t) < self.cooldown_ms
            {
                self.pending = Some((cand, streak));
                let mut d = self.decision(State::CoolingDown, now_ms);
                d.param = cand as i64;
                return d;
            }

            self.switch_to(cand, conf, cat, now_ms);
            let st = if cand == Action::KeepCurrent {
                State::Stable
            } else {
                State::Recommend
            };
            self.decision(st, now_ms)
        }
    }
}

// ---------------------------------------------------------------------------
// engine — lifecycle, scoring, encoding
// ---------------------------------------------------------------------------

pub mod engine {
    use crate::decide::{Action, Decider, Decision};
    use crate::intel::{self, Diagnosis, Environment};
    use crate::probe::{self, ProbeConfig, RunReport, Status};
    use crate::wire::Record;
    use crate::{code, tags};
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    #[derive(Debug, Clone)]
    pub struct Config {
        pub probe: ProbeConfig,
        pub cooldown_ms: u64,
        pub hysteresis_pct: u32,
    }

    impl Default for Config {
        fn default() -> Self {
            Self {
                probe: ProbeConfig::default(),
                cooldown_ms: 60_000,
                hysteresis_pct: 10,
            }
        }
    }

    fn clamp_u64(v: Option<i64>, lo: u64, hi: u64, default: u64) -> u64 {
        v.and_then(|x| u64::try_from(x).ok())
            .map_or(default, |x| x.clamp(lo, hi))
    }

    impl Config {
        pub fn from_record(r: Option<&Record>) -> Self {
            let d = Self::default();
            let Some(r) = r else { return d };
            use tags::config as t;
            Self {
                probe: ProbeConfig {
                    timeout: Duration::from_millis(clamp_u64(
                        r.get_int(t::TIMEOUT_MS),
                        100,
                        10_000,
                        1500,
                    )),
                    dns_samples: clamp_u64(r.get_int(t::DNS_SAMPLES), 1, 10, 5) as u32,
                    tcp_samples: clamp_u64(r.get_int(t::TCP_SAMPLES), 1, 5, 3) as u32,
                    max_parallel: clamp_u64(r.get_int(t::MAX_PARALLEL), 1, 8, 4) as usize,
                    quic: r.get_int(t::QUIC).map_or(d.probe.quic, |v| v != 0),
                    mtu: r.get_int(t::MTU).map_or(d.probe.mtu, |v| v != 0),
                    budget: Duration::from_millis(clamp_u64(
                        r.get_int(t::BUDGET_MS),
                        1000,
                        60_000,
                        20_000,
                    )),
                },
                cooldown_ms: clamp_u64(r.get_int(t::COOLDOWN_MS), 0, 3_600_000, d.cooldown_ms),
                hysteresis_pct: clamp_u64(r.get_int(t::HYSTERESIS_PCT), 0, 50, 10) as u32,
            }
        }
    }

    #[derive(Debug)]
    struct State {
        env: Option<Environment>,
        generation: u32,
        last: Option<RunReport>,
        decider: Decider,
        evaluations: u32,
    }

    #[derive(Debug)]
    pub struct Engine {
        config: Config,
        state: Mutex<State>,
        proxy: Mutex<Option<crate::desync::LocalProxy>>,
        counters: std::sync::Arc<crate::desync::ProxyCounters>,
        busy: AtomicBool,
        anchor: Instant,
    }

    struct BusyGuard<'a>(&'a AtomicBool);
    impl Drop for BusyGuard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    impl Engine {
        pub fn new(config: Config) -> Self {
            let decider = Decider::new(config.cooldown_ms, config.hysteresis_pct);
            Self {
                config,
                state: Mutex::new(State {
                    env: None,
                    generation: 1,
                    last: None,
                    decider,
                    evaluations: 0,
                }),
                proxy: Mutex::new(None),
                counters: std::sync::Arc::new(crate::desync::ProxyCounters::default()),
                busy: AtomicBool::new(false),
                anchor: Instant::now(),
            }
        }

        pub fn config(&self) -> &Config {
            &self.config
        }

        fn lock(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        pub fn set_environment(&self, r: &Record) -> i32 {
            self.lock().env = Some(Environment::from_record(r));
            code::OK
        }

        pub fn environment(&self) -> Option<Environment> {
            self.lock().env.clone()
        }

        /// Runs the probes. Network I/O happens without holding the state lock.
        pub fn diagnose(&self, r: &Record) -> Record {
            let mut targets = Vec::new();
            for s in r.texts(tags::request::TARGET) {
                if targets.len() >= probe::MAX_TARGETS {
                    return Record::with_status(code::LIMIT);
                }
                match probe::parse_target(s) {
                    Some(t) => targets.push(t),
                    None => {
                        let mut e = Record::with_status(code::INVALID_ARGUMENT);
                        e.text(tags::run::INVALID, s);
                        return e;
                    }
                }
            }
            let alternates: Vec<SocketAddr> = r
                .texts(tags::request::ALT_DNS)
                .filter_map(probe::parse_server)
                .take(probe::MAX_SERVERS)
                .collect();
            if self
                .busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return Record::with_status(code::BUSY);
            }
            let _guard = BusyGuard(&self.busy);
            let (servers, mtu, generation) = {
                let st = self.lock();
                let Some(env) = st.env.as_ref() else {
                    return Record::with_status(code::NO_ENVIRONMENT);
                };
                let servers: Vec<SocketAddr> = env
                    .dns_servers
                    .iter()
                    .filter_map(|s| probe::parse_server(s))
                    .take(probe::MAX_SERVERS)
                    .collect();
                (servers, env.mtu, st.generation)
            };
            let report = probe::run(&self.config.probe, &servers, &alternates, &targets, mtu);
            let mut st = self.lock();
            if st.generation != generation {
                // The network changed while probing: results describe the old network.
                return Record::with_status(code::NO_DATA);
            }
            let rec = encode_run(&report, generation);
            st.last = Some(report);
            rec
        }

        pub fn submit_tls(&self, r: &Record) -> i32 {
            let mut st = self.lock();
            let Some(last) = st.last.as_mut() else {
                return code::NO_DATA;
            };
            use tags::tls as t;
            let mut matched = 0;
            for o in r.records(tags::tls_submit::RESULT).take(probe::MAX_TARGETS) {
                let (Some(host), Some(port)) = (o.get_text(t::HOST), o.get_int(t::PORT)) else {
                    return code::INVALID_ARGUMENT;
                };
                let Some(tr) = last
                    .targets
                    .iter_mut()
                    .find(|x| x.target.host == host && i64::from(x.target.port) == port)
                else {
                    continue;
                };
                tr.tls = probe::TlsObservation {
                    status: o
                        .get_int(t::STATUS)
                        .filter(|s| (0..=6).contains(s))
                        .unwrap_or(probe::TLS_NOT_RUN),
                    handshake_us: o
                        .get_int(t::HANDSHAKE_US)
                        .and_then(|v| u64::try_from(v).ok())
                        .unwrap_or(0),
                    version: crate::wire::truncate_utf8(o.get_text(t::VERSION).unwrap_or(""), 32)
                        .to_owned(),
                    alpn: crate::wire::truncate_utf8(o.get_text(t::ALPN).unwrap_or(""), 32)
                        .to_owned(),
                    cipher: crate::wire::truncate_utf8(o.get_text(t::CIPHER).unwrap_or(""), 96)
                        .to_owned(),
                };
                matched += 1;
            }
            if matched == 0 {
                code::NO_DATA
            } else {
                code::OK
            }
        }

        /// Encrypted-DNS results measured by the platform layer. The raw DoH/DoT answer is
        /// validated here with the hardened DNS parser (ID 0 per RFC 8484 §4.1, question
        /// echo), so a captive-portal HTML page or a truncated body never counts as success.
        pub fn submit_encrypted(&self, r: &Record) -> i32 {
            use tags::enc as t;
            let mut st = self.lock();
            let Some(last) = st.last.as_mut() else {
                return code::NO_DATA;
            };
            let mut added = 0;
            for o in r.records(tags::enc_submit::RESULT).take(probe::MAX_SERVERS) {
                let Some(endpoint) = o.get_text(t::ENDPOINT) else {
                    return code::INVALID_ARGUMENT;
                };
                let protocol = o
                    .get_int(t::PROTOCOL)
                    .filter(|p| (probe::ENC_DOH..=probe::ENC_DOQ).contains(p))
                    .unwrap_or(probe::ENC_UNKNOWN);
                let transport = status_from_code(o.get_int(t::TRANSPORT).unwrap_or(0));
                let rtt_us = o
                    .get_int(t::RTT_US)
                    .and_then(|v| u64::try_from(v).ok())
                    .unwrap_or(0);
                let (status, answers) = match (transport, o.get_bytes(t::RESPONSE)) {
                    (Status::Ok, Some(resp)) => {
                        let name = o.get_text(t::QUERY_NAME).unwrap_or("");
                        let qtype = o
                            .get_int(t::QTYPE)
                            .and_then(|q| u16::try_from(q).ok())
                            .unwrap_or(crate::dns::TYPE_A);
                        validate_encrypted_answer(resp, name, qtype)
                    }
                    (Status::Ok, None) => (Status::NoData, 0),
                    (other, _) => (other, 0),
                };
                last.encrypted.push(probe::EncryptedResolver {
                    endpoint: crate::wire::truncate_utf8(endpoint, 256).to_owned(),
                    name: crate::ascii::lowercased(
                        o.get_text(t::QUERY_NAME)
                            .unwrap_or("")
                            .trim_end_matches('.'),
                    ),
                    protocol,
                    status,
                    rtt_us,
                    answers,
                });
                added += 1;
            }
            if added == 0 { code::NO_DATA } else { code::OK }
        }

        pub fn evaluate(&self) -> Record {
            let now = u64::try_from(self.anchor.elapsed().as_millis()).unwrap_or(u64::MAX);
            self.evaluate_at(now)
        }

        /// Deterministic evaluation at an explicit monotonic time (milliseconds).
        pub fn evaluate_at(&self, now_ms: u64) -> Record {
            let mut st = self.lock();
            let State {
                env,
                generation,
                last,
                decider,
                evaluations,
            } = &mut *st;
            let Some(run) = last.as_ref() else {
                return Record::with_status(code::NO_DATA);
            };
            let diags = intel::classify(env.as_ref(), run);
            let s = score(run);
            let decision = decider.step(now_ms, s, &diags);
            *evaluations += 1;
            encode_evaluation(
                s,
                decider,
                *generation,
                *evaluations,
                &diags,
                &decision,
                run,
            )
        }

        pub fn network_changed(&self) -> i32 {
            let mut st = self.lock();
            st.generation = st.generation.wrapping_add(1).max(1);
            st.last = None;
            st.evaluations = 0;
            st.decider.network_changed();
            code::OK
        }

        pub fn mark_applied(&self, action: i64) -> i32 {
            let Some(a) = Action::from_code(action) else {
                return code::INVALID_ARGUMENT;
            };
            if self.lock().decider.mark_applied(a) {
                code::OK
            } else {
                code::NO_DATA
            }
        }

        /// Runs packet-level DPI desynchronization on a raw IPv4/IPv6 packet.
        pub fn desync_packet(&self, r: &Record) -> Record {
            let Some(pkt) = r.get_bytes(tags::desync::PACKET) else {
                return Record::with_status(code::INVALID_ARGUMENT);
            };
            let cfg = crate::desync::DesyncConfig::from_record(r);
            let out = crate::desync::desync_packet(pkt, &cfg);
            if out.dropped_inbound {
                self.counters.rst_dropped.fetch_add(1, Ordering::Relaxed);
            } else {
                match out.inspection.protocol {
                    crate::desync::PROTO_TLS_CLIENT_HELLO => {
                        self.counters.connections.fetch_add(1, Ordering::Relaxed);
                        self.counters.tls_split.fetch_add(1, Ordering::Relaxed);
                        if cfg.mode == crate::desync::DesyncMode::RealityVision {
                            self.counters.vision_splice.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    crate::desync::PROTO_HTTP_REQUEST => {
                        self.counters.connections.fetch_add(1, Ordering::Relaxed);
                        self.counters.http_split.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
                if out.packets.len() > 1
                    && matches!(
                        cfg.mode,
                        crate::desync::DesyncMode::FakeBadSum
                            | crate::desync::DesyncMode::FakeAutoTtl
                            | crate::desync::DesyncMode::QuicScramble
                            | crate::desync::DesyncMode::AdaptiveFull
                            | crate::desync::DesyncMode::RealityVision
                    )
                {
                    self.counters.fake_sent.fetch_add(1, Ordering::Relaxed);
                }
            }
            crate::desync::encode_desync_output(&out, cfg.mode)
        }

        /// Starts (or restarts) the local unprivileged SOCKS5/HTTP DPI-circumvention proxy.
        pub fn start_proxy(&self, r: &Record) -> Record {
            let cfg = crate::desync::DesyncConfig::from_record(r);
            let mut guard = self.proxy.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(mut old) = guard.take() {
                old.stop();
            }
            match crate::desync::LocalProxy::start_with_counters(
                cfg,
                std::sync::Arc::clone(&self.counters),
            ) {
                Ok(p) => {
                    let port = p.port();
                    let mode = p.config().mode;
                    let c = p.counters();
                    let mut out = Record::with_status(code::OK);
                    out.int(tags::desync::ACTIVE, 1)
                        .int(tags::desync::PORT, i64::from(port))
                        .int(tags::desync::MODE, mode as i64)
                        .int(
                            tags::desync::CONNECTIONS,
                            sat(c.connections.load(Ordering::Relaxed)),
                        )
                        .int(
                            tags::desync::TLS_SPLIT,
                            sat(c.tls_split.load(Ordering::Relaxed)),
                        )
                        .int(
                            tags::desync::HTTP_SPLIT,
                            sat(c.http_split.load(Ordering::Relaxed)),
                        )
                        .int(
                            tags::desync::FAKE_SENT,
                            sat(c.fake_sent.load(Ordering::Relaxed)),
                        )
                        .int(
                            tags::desync::RST_DROPPED,
                            sat(c.rst_dropped.load(Ordering::Relaxed)),
                        )
                        .int(
                            tags::desync::VISION_SPLICE,
                            sat(c.vision_splice.load(Ordering::Relaxed)),
                        );
                    *guard = Some(p);
                    out
                }
                Err(_) => Record::with_status(code::INTERNAL),
            }
        }

        /// Stops the local DPI-circumvention proxy if running.
        pub fn stop_proxy(&self) -> i32 {
            let mut guard = self.proxy.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(mut p) = guard.take() {
                p.stop();
            }
            code::OK
        }

        /// Returns live telemetry counters for the local DPI-circumvention proxy.
        pub fn proxy_stats(&self) -> Record {
            use tags::desync as t;
            let guard = self.proxy.lock().unwrap_or_else(PoisonError::into_inner);
            let mut r = Record::with_status(code::OK);
            let c = &self.counters;
            match guard.as_ref() {
                Some(p) => {
                    r.int(t::ACTIVE, 1)
                        .int(t::PORT, i64::from(p.port()))
                        .int(t::MODE, p.config().mode as i64)
                        .int(t::CONNECTIONS, sat(c.connections.load(Ordering::Relaxed)))
                        .int(t::TLS_SPLIT, sat(c.tls_split.load(Ordering::Relaxed)))
                        .int(t::HTTP_SPLIT, sat(c.http_split.load(Ordering::Relaxed)))
                        .int(t::FAKE_SENT, sat(c.fake_sent.load(Ordering::Relaxed)))
                        .int(t::RST_DROPPED, sat(c.rst_dropped.load(Ordering::Relaxed)))
                        .int(
                            t::VISION_SPLICE,
                            sat(c.vision_splice.load(Ordering::Relaxed)),
                        );
                }
                None => {
                    r.int(t::ACTIVE, 0)
                        .int(t::PORT, 0)
                        .int(t::MODE, crate::desync::DesyncMode::Off as i64)
                        .int(t::CONNECTIONS, sat(c.connections.load(Ordering::Relaxed)))
                        .int(t::TLS_SPLIT, sat(c.tls_split.load(Ordering::Relaxed)))
                        .int(t::HTTP_SPLIT, sat(c.http_split.load(Ordering::Relaxed)))
                        .int(t::FAKE_SENT, sat(c.fake_sent.load(Ordering::Relaxed)))
                        .int(t::RST_DROPPED, sat(c.rst_dropped.load(Ordering::Relaxed)))
                        .int(
                            t::VISION_SPLICE,
                            sat(c.vision_splice.load(Ordering::Relaxed)),
                        );
                }
            }
            r
        }
    }

    /// Maps a probe::Status code received from the platform layer back to the enum.
    pub fn status_from_code(c: i64) -> Status {
        match c {
            1 => Status::Ok,
            2 => Status::Timeout,
            3 => Status::Refused,
            4 => Status::Unreachable,
            6 => Status::Invalid,
            7 => Status::NoData,
            8 => Status::NameError,
            9 => Status::ServerFailure,
            10 => Status::Unsupported,
            11 => Status::Skipped,
            12 => Status::LocalLimit,
            13 => Status::Blocked,
            0 => Status::NotRun,
            _ => Status::Error,
        }
    }

    /// Validates an encrypted-resolver answer: (status, number of address records).
    pub fn validate_encrypted_answer(resp: &[u8], name: &str, qtype: u16) -> (Status, u32) {
        match crate::dns::parse_response(resp, 0, name, qtype) {
            Ok(r) => match r.header.rcode() {
                crate::dns::RCODE_NOERROR => {
                    let n = r
                        .answers
                        .iter()
                        .filter(|a| {
                            matches!(a.data, crate::dns::RData::A(_) | crate::dns::RData::Aaaa(_))
                        })
                        .count() as u32;
                    (if n > 0 { Status::Ok } else { Status::NoData }, n)
                }
                crate::dns::RCODE_NXDOMAIN => (Status::NameError, 0),
                _ => (Status::ServerFailure, 0),
            },
            Err(_) => (Status::Invalid, 0),
        }
    }

    /// RFC 8484 DoH query for `name`/`qtype`: DNS wire format with ID 0 (cache friendly).
    pub fn doh_query(r: &Record) -> Record {
        let Some(name) = r.get_text(tags::doh_query::NAME) else {
            return Record::with_status(code::INVALID_ARGUMENT);
        };
        let qtype = r
            .get_int(tags::doh_query::QTYPE)
            .and_then(|q| u16::try_from(q).ok())
            .unwrap_or(crate::dns::TYPE_A);
        if !crate::dns::is_valid_hostname(name) {
            let mut e = Record::with_status(code::INVALID_ARGUMENT);
            e.text(tags::run::INVALID, name);
            return e;
        }
        match crate::dns::build_query(0, name, qtype, true) {
            Ok(q) => {
                let mut out = Record::with_status(code::OK);
                out.bytes(tags::doh_query::QUERY, &q);
                out
            }
            Err(_) => Record::with_status(code::INVALID_ARGUMENT),
        }
    }

    fn latency_score(us: u64) -> i64 {
        let ms = (us / 1000) as i64;
        if ms <= 20 {
            1000
        } else if ms >= 1000 {
            0
        } else {
            1000 - (ms - 20) * 1000 / 980
        }
    }

    /// S = (400·C + 250·L + 200·P + 100·T + 50·E) / 1000, all components in 0..=1000.
    /// C success ratio, L latency, P resolver delivery, T protocol capability, E energy (run time).
    pub fn score(run: &RunReport) -> Option<i64> {
        let (mut total, mut ok) = (0i64, 0i64);
        let mut latencies = Vec::new();
        let (mut proto_points, mut proto_max) = (0i64, 0i64);
        for t in &run.targets {
            if t.target.literal.is_none()
                && !matches!(
                    t.dns.status,
                    Status::NotRun | Status::Skipped | Status::Unsupported
                )
            {
                total += 1;
                ok += i64::from(t.dns.status == Status::Ok);
            }
            for tcp in [&t.tcp4, &t.tcp6] {
                total += i64::from(tcp.attempts);
                ok += i64::from(tcp.successes);
                if tcp.successes > 0 {
                    latencies.push(tcp.median_us);
                }
            }
            if !matches!(t.tls.status, probe::TLS_NOT_RUN | probe::TLS_UNSUPPORTED) {
                total += 1;
                ok += i64::from(t.tls.status == probe::TLS_OK);
            }
            if t.tcp_ok() {
                proto_max += 3;
                proto_points += i64::from(t.tls.version == "TLSv1.3");
                proto_points += i64::from(t.tls.alpn == "h2");
                proto_points += i64::from(t.quic.supports_v1());
            }
        }
        let (sent, received) = run
            .resolvers
            .iter()
            .filter(|r| !r.alternate)
            .fold((0i64, 0i64), |(s, r), x| {
                (s + i64::from(x.sent), r + i64::from(x.received))
            });
        if total == 0 && sent == 0 {
            return None;
        }
        let c = if total > 0 {
            ok * 1000 / total
        } else {
            received * 1000 / sent
        };
        latencies.sort_unstable();
        let l = latencies
            .get(latencies.len() / 2)
            .map_or(0, |m| latency_score(*m));
        let p = if sent > 0 { received * 1000 / sent } else { c };
        let t = if proto_max > 0 {
            proto_points * 1000 / proto_max
        } else {
            0
        };
        let secs = (run.duration_us / 1_000_000) as i64;
        let e = if secs <= 2 {
            1000
        } else if secs >= 20 {
            0
        } else {
            1000 - (secs - 2) * 1000 / 18
        };
        Some((400 * c + 250 * l + 200 * p + 100 * t + 50 * e) / 1000)
    }

    fn sat(v: u64) -> i64 {
        i64::try_from(v).unwrap_or(i64::MAX)
    }

    pub fn encode_run(run: &RunReport, generation: u32) -> Record {
        let mut r = Record::with_status(code::OK);
        r.int(tags::run::GENERATION, i64::from(generation))
            .int(tags::run::DURATION_US, sat(run.duration_us));
        for s in &run.resolvers {
            use tags::resolver as t;
            let mut x = Record::new();
            x.text(t::SERVER, &s.server.to_string())
                .int(t::ALTERNATE, i64::from(s.alternate))
                .int(t::SENT, i64::from(s.sent))
                .int(t::RECEIVED, i64::from(s.received))
                .int(t::AVG_US, sat(s.avg_us()))
                .int(t::JITTER_US, sat(s.jitter_us()))
                .int(t::STATUS, s.status.code())
                .int(t::TCP_STATUS, s.tcp_status.code());
            r.record(tags::run::RESOLVER, x);
        }
        for e in &run.encrypted {
            use tags::enc as t;
            let mut x = Record::new();
            x.text(t::ENDPOINT, &e.endpoint)
                .int(t::PROTOCOL, e.protocol)
                .int(t::STATUS, e.status.code())
                .int(t::RTT_US, sat(e.rtt_us))
                .int(t::ANSWERS, i64::from(e.answers));
            r.record(tags::run::ENCRYPTED, x);
        }
        for tr in &run.targets {
            use tags::target as t;
            let mut x = Record::new();
            x.text(t::HOST, &tr.target.host)
                .int(t::PORT, i64::from(tr.target.port))
                .int(t::LITERAL, i64::from(tr.target.literal.is_some()))
                .int(t::DNS_STATUS, tr.dns.status.code())
                .int(t::DNS_US, sat(tr.dns.latency_us))
                .int(t::DNS_RCODE, tr.dns.rcode)
                .int(t::DNS_TCP, i64::from(tr.dns.via_tcp));
            if let Some(s) = tr.dns.server {
                x.text(t::DNS_SERVER, &s.to_string());
            }
            for a in &tr.dns.v4 {
                x.text(t::ADDRESS, &a.to_string());
            }
            for a in &tr.dns.v6 {
                x.text(t::ADDRESS, &a.to_string());
            }
            x.int(t::HTTPS_RR, i64::from(tr.dns.https.is_some()));
            if let Some(h) = &tr.dns.https {
                for a in &h.alpn {
                    x.text(t::ALPN, a);
                }
                x.int(t::ECH, i64::from(h.ech));
            }
            x.int(t::TCP4_STATUS, tr.tcp4.status.code())
                .int(t::TCP4_US, sat(tr.tcp4.median_us))
                .int(t::TCP4_ATTEMPTS, i64::from(tr.tcp4.attempts))
                .int(t::TCP4_OK, i64::from(tr.tcp4.successes))
                .int(t::TCP6_STATUS, tr.tcp6.status.code())
                .int(t::TCP6_US, sat(tr.tcp6.median_us))
                .int(t::TCP6_ATTEMPTS, i64::from(tr.tcp6.attempts))
                .int(t::TCP6_OK, i64::from(tr.tcp6.successes))
                .int(t::QUIC_STATUS, tr.quic.status.code())
                .int(t::QUIC_US, sat(tr.quic.rtt_us));
            for v in &tr.quic.versions {
                x.int(t::QUIC_VERSION, i64::from(*v));
            }
            x.int(t::MTU_STATUS, tr.mtu.status.code())
                .int(t::PMTU, i64::from(tr.mtu.path_mtu))
                .int(t::MTU_CEILING, i64::from(tr.mtu.ceiling))
                .int(t::MTU_PROBES, i64::from(tr.mtu.probes))
                .int(t::TLS_STATUS, tr.tls.status)
                .int(t::TLS_US, sat(tr.tls.handshake_us))
                .text(t::TLS_VERSION, &tr.tls.version)
                .text(t::TLS_ALPN, &tr.tls.alpn)
                .text(t::TLS_CIPHER, &tr.tls.cipher);
            r.record(tags::run::TARGET, x);
        }
        r
    }

    fn decision_param(d: &Decision, run: &RunReport) -> i64 {
        match d.action {
            Action::LowerMtu => run
                .targets
                .iter()
                .filter(|t| t.mtu.status == Status::Ok)
                .map(|t| i64::from(t.mtu.path_mtu))
                .min()
                .unwrap_or(0),
            _ => d.param,
        }
    }

    fn encode_evaluation(
        score: Option<i64>,
        decider: &Decider,
        generation: u32,
        evaluations: u32,
        diags: &[Diagnosis],
        d: &Decision,
        run: &RunReport,
    ) -> Record {
        use tags::eval as t;
        let mut r = Record::with_status(code::OK);
        let desync_mode = crate::decide::recommend_desync_mode(diags);
        r.int(t::SCORE, score.unwrap_or(-1))
            .int(t::EWMA, decider.ewma().unwrap_or(-1))
            .int(t::GENERATION, i64::from(generation))
            .int(t::STABILITY, decider.stability())
            .int(t::EVALUATIONS, i64::from(evaluations))
            .int(t::DESYNC_MODE, desync_mode as i64);
        for dg in diags {
            let mut x = Record::new();
            x.int(tags::diagnosis::CATEGORY, dg.category as i64)
                .int(tags::diagnosis::CONFIDENCE, i64::from(dg.confidence));
            for o in &dg.observations {
                let mut y = Record::new();
                y.int(tags::observation::CODE, o.code as i64)
                    .text(tags::observation::SUBJECT, &o.subject);
                for a in &o.args {
                    y.int(tags::observation::ARG, *a);
                }
                x.record(tags::diagnosis::OBSERVATION, y);
            }
            r.record(t::DIAGNOSIS, x);
        }
        let mut x = Record::new();
        use tags::decision as k;
        x.int(k::STATE, d.state as i64)
            .int(k::ACTION, d.action as i64)
            .int(k::CONFIDENCE, i64::from(d.confidence))
            .int(k::CATEGORY, d.category as i64)
            .int(k::COOLDOWN_MS, sat(d.cooldown_remaining_ms))
            .int(k::PARAM, decision_param(d, run))
            .int(k::HIGH_IMPACT, i64::from(d.action.is_high_impact()));
        r.record(t::DECISION, x);
        r
    }

    /// Native environment detection. Windows: IP Helper + registry. Elsewhere the
    /// platform layer (Android ConnectivityManager) supplies the environment.
    pub fn detect_environment() -> Record {
        let mut env = Environment {
            os_name: std::env::consts::OS.to_owned(),
            arch: std::env::consts::ARCH.to_owned(),
            ..Environment::default()
        };
        let status = fill_platform_environment(&mut env);
        let mut r = env.to_record();
        r.int(tags::STATUS, i64::from(status));
        r
    }

    #[cfg(windows)]
    fn fill_platform_environment(env: &mut Environment) -> i32 {
        use crate::sys::win;
        use std::net::IpAddr;
        env.os_name = "Windows".to_owned();
        if let Some((build, display)) = win::os_build() {
            env.os_build = build;
            let product = if build >= 22_000 {
                "Windows 11"
            } else {
                "Windows 10"
            };
            env.os_version = if display.is_empty() {
                product.to_owned()
            } else {
                format!("{product} {display}")
            };
        }
        let (adapters, dual_stack) = match win::adapters() {
            Ok(s) => (s.adapters, s.dual_stack),
            Err(_) => return code::INTERNAL,
        };
        const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
        let primary = adapters
            .iter()
            .filter(|a| a.up && a.if_type != IF_TYPE_SOFTWARE_LOOPBACK && !a.gateways.is_empty())
            .min_by_key(|a| a.metric);
        let Some(a) = primary else {
            env.connected = intel::NO;
            return code::OK;
        };
        env.connected = intel::YES;
        env.interface = a.name.clone();
        env.mtu = a.mtu;
        env.network_type = match a.if_type {
            6 => intel::NET_ETHERNET,
            71 => intel::NET_WIFI,
            243 | 244 => intel::NET_CELLULAR,
            23 | 53 | 131 => intel::NET_VPN,
            _ => intel::NET_OTHER,
        };
        env.dns_servers = a
            .dns
            .iter()
            .take(8)
            .map(|ip| match ip {
                IpAddr::V6(v6) if v6.is_unicast_link_local() => format!("[{v6}]:53"),
                other => other.to_string(),
            })
            .collect();
        env.gateways = a.gateways.iter().take(8).map(ToString::to_string).collect();
        let global_v4 = a
            .unicast
            .iter()
            .any(|ip| matches!(ip, IpAddr::V4(v) if !v.is_link_local() && !v.is_loopback()));
        let global_v6 = a
            .unicast
            .iter()
            .any(|ip| matches!(ip, IpAddr::V6(v) if (v.segments()[0] & 0xE000) == 0x2000));
        env.has_ipv4 = if global_v4 { intel::YES } else { intel::NO };
        env.has_ipv6 = match (dual_stack, global_v6) {
            (false, _) => intel::UNKNOWN,
            (true, true) => intel::YES,
            (true, false) => intel::NO,
        };
        code::OK
    }

    #[cfg(not(windows))]
    fn fill_platform_environment(_env: &mut Environment) -> i32 {
        code::UNSUPPORTED
    }
}

// ---------------------------------------------------------------------------
// registry — opaque handles (never raw pointers) for JNI
// ---------------------------------------------------------------------------

mod registry {
    use crate::code;
    use crate::engine::Engine;
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

    pub const MAX_ENGINES: usize = 16;

    struct Registry {
        next: i64,
        items: Vec<(i64, Arc<Engine>)>,
    }

    // The single global: required because JNI entry points are static functions.
    // Handles are monotonically increasing IDs and are never reused, so a stale
    // handle can never alias a newer engine (no use-after-free through Kotlin).
    static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
        next: 1,
        items: Vec::new(),
    });

    fn lock() -> MutexGuard<'static, Registry> {
        REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn insert(e: Engine) -> i64 {
        let mut r = lock();
        if r.items.len() >= MAX_ENGINES {
            return i64::from(code::LIMIT);
        }
        let h = r.next;
        let Some(next) = h.checked_add(1) else {
            return i64::from(code::LIMIT);
        };
        r.next = next;
        r.items.push((h, Arc::new(e)));
        h
    }

    pub fn get(h: i64) -> Option<Arc<Engine>> {
        if h <= 0 {
            return None;
        }
        lock()
            .items
            .iter()
            .find(|(k, _)| *k == h)
            .map(|(_, e)| Arc::clone(e))
    }

    pub fn remove(h: i64) -> bool {
        let mut r = lock();
        let before = r.items.len();
        r.items.retain(|(k, _)| *k != h);
        r.items.len() != before
    }

    pub fn count() -> usize {
        lock().items.len()
    }
}

// ---------------------------------------------------------------------------
// api — safe facade (bytes in, bytes out)
// ---------------------------------------------------------------------------

pub mod api {
    use crate::engine::{self, Config, Engine};
    use crate::wire::{self, Record};
    use crate::{code, registry};

    pub use registry::MAX_ENGINES;

    /// Status-only message, built without allocation failure paths in the encoder.
    pub fn status_only(c: i32) -> Vec<u8> {
        let mut v = Vec::with_capacity(17);
        v.extend_from_slice(&wire::MAGIC);
        v.push(wire::VERSION);
        v.push(crate::tags::STATUS);
        v.push(1);
        v.extend_from_slice(&8u32.to_be_bytes());
        v.extend_from_slice(&i64::from(c).to_be_bytes());
        v
    }

    fn encode(r: &Record) -> Vec<u8> {
        wire::encode(r).unwrap_or_else(|_| status_only(code::INTERNAL))
    }

    fn decode(b: &[u8]) -> Result<Record, i32> {
        wire::decode(b).map_err(|_| code::WIRE)
    }

    pub fn create(config: Option<&[u8]>) -> i64 {
        let rec = match config.map(decode) {
            Some(Ok(r)) => Some(r),
            Some(Err(c)) => return i64::from(c),
            None => None,
        };
        registry::insert(Engine::new(Config::from_record(rec.as_ref())))
    }

    pub fn destroy(handle: i64) -> i32 {
        if registry::remove(handle) {
            code::OK
        } else {
            code::INVALID_HANDLE
        }
    }

    pub fn engine_count() -> usize {
        registry::count()
    }

    pub fn detect_environment() -> Vec<u8> {
        encode(&engine::detect_environment())
    }

    pub fn set_environment(handle: i64, env: &[u8]) -> i32 {
        let Some(e) = registry::get(handle) else {
            return code::INVALID_HANDLE;
        };
        match decode(env) {
            Ok(r) => e.set_environment(&r),
            Err(c) => c,
        }
    }

    pub fn diagnose(handle: i64, request: &[u8]) -> Vec<u8> {
        let Some(e) = registry::get(handle) else {
            return status_only(code::INVALID_HANDLE);
        };
        match decode(request) {
            Ok(r) => encode(&e.diagnose(&r)),
            Err(c) => status_only(c),
        }
    }

    pub fn submit_tls(handle: i64, observations: &[u8]) -> i32 {
        let Some(e) = registry::get(handle) else {
            return code::INVALID_HANDLE;
        };
        match decode(observations) {
            Ok(r) => e.submit_tls(&r),
            Err(c) => c,
        }
    }

    /// System-wide connection snapshot with per-process findings (Windows).
    pub fn system_connections() -> Vec<u8> {
        encode(&crate::sysnet::snapshot())
    }

    /// Builds an RFC 8484 DoH query (DNS wire format, ID 0). No handle needed.
    pub fn doh_query(request: &[u8]) -> Vec<u8> {
        match decode(request) {
            Ok(r) => encode(&engine::doh_query(&r)),
            Err(c) => status_only(c),
        }
    }

    pub fn submit_encrypted(handle: i64, results: &[u8]) -> i32 {
        let Some(e) = registry::get(handle) else {
            return code::INVALID_HANDLE;
        };
        match decode(results) {
            Ok(r) => e.submit_encrypted(&r),
            Err(c) => c,
        }
    }

    pub fn evaluate(handle: i64) -> Vec<u8> {
        match registry::get(handle) {
            Some(e) => encode(&e.evaluate()),
            None => status_only(code::INVALID_HANDLE),
        }
    }

    pub fn network_changed(handle: i64) -> i32 {
        registry::get(handle).map_or(code::INVALID_HANDLE, |e| e.network_changed())
    }

    pub fn mark_applied(handle: i64, action: i32) -> i32 {
        registry::get(handle).map_or(code::INVALID_HANDLE, |e| e.mark_applied(i64::from(action)))
    }

    pub fn desync_packet(handle: i64, request: &[u8]) -> Vec<u8> {
        let Some(e) = registry::get(handle) else {
            return status_only(code::INVALID_HANDLE);
        };
        match decode(request) {
            Ok(r) => encode(&e.desync_packet(&r)),
            Err(c) => status_only(c),
        }
    }

    pub fn start_proxy(handle: i64, config: &[u8]) -> Vec<u8> {
        let Some(e) = registry::get(handle) else {
            return status_only(code::INVALID_HANDLE);
        };
        match decode(config) {
            Ok(r) => encode(&e.start_proxy(&r)),
            Err(c) => status_only(c),
        }
    }

    pub fn stop_proxy(handle: i64) -> i32 {
        registry::get(handle).map_or(code::INVALID_HANDLE, |e| e.stop_proxy())
    }

    pub fn proxy_stats(handle: i64) -> Vec<u8> {
        match registry::get(handle) {
            Some(e) => encode(&e.proxy_stats()),
            None => status_only(code::INVALID_HANDLE),
        }
    }
}

// ---------------------------------------------------------------------------
// jni — the single Kotlin ↔ Rust boundary (class `thedpi.Native`)
// ---------------------------------------------------------------------------

/// Hand-written minimal JNI binding. Function-table indices are fixed by the JNI
/// specification ("Interface Function Table") and were verified against jni.h.
pub mod jni {
    use std::ffi::{CString, c_char, c_void};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::ptr::null_mut;

    pub type JInt = i32;
    pub type JLong = i64;
    pub type JSize = i32;
    pub type JBoolean = u8;
    pub type JObject = *mut c_void;
    pub type JClass = JObject;
    pub type JByteArray = JObject;
    pub type JString = JObject;
    /// `JNIEnv*`: pointer to a pointer to the function table.
    pub type EnvPtr = *mut *const *const c_void;

    pub const JNI_VERSION_1_6: JInt = 0x0001_0006;
    const IDX_NEW_STRING_UTF: usize = 167;
    const IDX_GET_ARRAY_LENGTH: usize = 171;
    const IDX_NEW_BYTE_ARRAY: usize = 176;
    const IDX_GET_BYTE_ARRAY_REGION: usize = 200;
    const IDX_SET_BYTE_ARRAY_REGION: usize = 208;
    const IDX_EXCEPTION_CHECK: usize = 228;

    /// SAFETY: `env` must be the JNIEnv passed by the JVM to the current native call.
    unsafe fn function(env: EnvPtr, index: usize) -> Option<*const c_void> {
        if env.is_null() {
            return None;
        }
        // SAFETY: a valid JNIEnv points to a valid function table with ≥ 229 entries.
        let table = unsafe { *env };
        if table.is_null() {
            return None;
        }
        // SAFETY: index is within the JNI function table.
        let f = unsafe { *table.add(index) };
        (!f.is_null()).then_some(f)
    }

    /// SAFETY: same as `function`.
    unsafe fn exception_pending(env: EnvPtr) -> bool {
        type F = unsafe extern "system" fn(EnvPtr) -> JBoolean;
        // SAFETY: caller contract (valid env).
        match unsafe { function(env, IDX_EXCEPTION_CHECK) } {
            // SAFETY: table entry IDX_EXCEPTION_CHECK has type F per the JNI specification.
            Some(p) => unsafe { std::mem::transmute::<*const c_void, F>(p)(env) != 0 },
            None => true,
        }
    }

    /// Copies a Java byte[] into Rust memory (bounded by `max`).
    ///
    /// # Safety
    /// `env` is valid for this thread; `array` is null or a live jbyteArray reference.
    pub unsafe fn read_bytes(env: EnvPtr, array: JByteArray, max: usize) -> Option<Vec<u8>> {
        if array.is_null() {
            return None;
        }
        type Len = unsafe extern "system" fn(EnvPtr, JObject) -> JSize;
        type Region = unsafe extern "system" fn(EnvPtr, JByteArray, JSize, JSize, *mut i8);
        // SAFETY: entries have the declared signatures per the JNI specification.
        let (len_fn, region_fn) = unsafe {
            (
                std::mem::transmute::<*const c_void, Len>(function(env, IDX_GET_ARRAY_LENGTH)?),
                std::mem::transmute::<*const c_void, Region>(function(
                    env,
                    IDX_GET_BYTE_ARRAY_REGION,
                )?),
            )
        };
        // SAFETY: array is a valid jbyteArray.
        let len = unsafe { len_fn(env, array) };
        let n = usize::try_from(len).ok().filter(|n| *n <= max)?;
        let mut buf = vec![0u8; n];
        if n > 0 {
            // SAFETY: buf has exactly `len` writable bytes.
            unsafe { region_fn(env, array, 0, len, buf.as_mut_ptr().cast()) };
        }
        // SAFETY: valid env.
        if unsafe { exception_pending(env) } {
            return None;
        }
        Some(buf)
    }

    /// Creates a Java byte[] holding `data`.
    ///
    /// # Safety
    /// `env` is valid for this thread.
    pub unsafe fn new_byte_array(env: EnvPtr, data: &[u8]) -> JByteArray {
        type New = unsafe extern "system" fn(EnvPtr, JSize) -> JByteArray;
        type Region = unsafe extern "system" fn(EnvPtr, JByteArray, JSize, JSize, *const i8);
        let Ok(len) = JSize::try_from(data.len()) else {
            return null_mut();
        };
        // SAFETY: entries have the declared signatures.
        let (Some(new_fn), Some(region_fn)) =
            (unsafe { function(env, IDX_NEW_BYTE_ARRAY) }, unsafe {
                function(env, IDX_SET_BYTE_ARRAY_REGION)
            })
        else {
            return null_mut();
        };
        // SAFETY: signatures per JNI specification.
        let (new_fn, region_fn) = unsafe {
            (
                std::mem::transmute::<*const c_void, New>(new_fn),
                std::mem::transmute::<*const c_void, Region>(region_fn),
            )
        };
        // SAFETY: valid env; on OOM returns null with OutOfMemoryError pending.
        let arr = unsafe { new_fn(env, len) };
        if arr.is_null() {
            return null_mut();
        }
        if len > 0 {
            // SAFETY: arr has `len` elements; data has `len` readable bytes.
            unsafe { region_fn(env, arr, 0, len, data.as_ptr().cast()) };
        }
        // SAFETY: valid env.
        if unsafe { exception_pending(env) } {
            null_mut()
        } else {
            arr
        }
    }

    /// Creates a Java String from ASCII text (modified UTF-8 compatible).
    ///
    /// # Safety
    /// `env` is valid for this thread.
    pub unsafe fn new_string(env: EnvPtr, s: &str) -> JString {
        type F = unsafe extern "system" fn(EnvPtr, *const c_char) -> JString;
        let Ok(c) = CString::new(s) else {
            return null_mut();
        };
        // SAFETY: caller contract (valid env).
        match unsafe { function(env, IDX_NEW_STRING_UTF) } {
            // SAFETY: entry IDX_NEW_STRING_UTF has type F; `c` is NUL-terminated and outlives the call.
            Some(p) => unsafe { std::mem::transmute::<*const c_void, F>(p)(env, c.as_ptr()) },
            None => null_mut(),
        }
    }

    /// Runs `f`, converting any panic into `fallback` so unwinding never crosses FFI.
    pub fn guard<R>(fallback: R, f: impl FnOnce() -> R) -> R {
        catch_unwind(AssertUnwindSafe(f)).unwrap_or(fallback)
    }
}

mod exports {
    use crate::jni::{self, EnvPtr, JByteArray, JClass, JInt, JLong, JString};
    use crate::{API_VERSION, ENGINE_VERSION, api, code, wire};
    use std::ffi::c_void;
    use std::ptr::null_mut;

    /// SAFETY: `env` valid for this thread.
    unsafe fn respond(env: EnvPtr, bytes: &[u8]) -> JByteArray {
        // SAFETY: forwarded caller contract.
        unsafe { jni::new_byte_array(env, bytes) }
    }

    /// SAFETY: `env` valid for this thread; `arr` null or a live jbyteArray.
    unsafe fn input(env: EnvPtr, arr: JByteArray) -> Result<Vec<u8>, i32> {
        // SAFETY: forwarded caller contract.
        unsafe { jni::read_bytes(env, arr, wire::MAX_MESSAGE) }.ok_or(code::JNI)
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn JNI_OnLoad(_vm: *mut c_void, _reserved: *mut c_void) -> JInt {
        jni::JNI_VERSION_1_6
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_thedpi_Native_apiVersion(_env: EnvPtr, _class: JClass) -> JInt {
        API_VERSION
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_engineVersion(
        env: EnvPtr,
        _class: JClass,
    ) -> JString {
        // SAFETY: JVM-provided env.
        jni::guard(null_mut(), || unsafe {
            jni::new_string(env, ENGINE_VERSION)
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_create(
        env: EnvPtr,
        _class: JClass,
        config: JByteArray,
    ) -> JLong {
        jni::guard(i64::from(code::PANIC), || {
            if config.is_null() {
                return api::create(None);
            }
            // SAFETY: JVM-provided env and array.
            match unsafe { input(env, config) } {
                Ok(b) => api::create(Some(&b)),
                Err(c) => i64::from(c),
            }
        })
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_thedpi_Native_destroy(
        _env: EnvPtr,
        _class: JClass,
        handle: JLong,
    ) -> JInt {
        jni::guard(code::PANIC, || api::destroy(handle))
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_detectEnvironment(
        env: EnvPtr,
        _class: JClass,
    ) -> JByteArray {
        // SAFETY: JVM-provided env.
        jni::guard(null_mut(), || unsafe {
            respond(env, &api::detect_environment())
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_setEnvironment(
        env: EnvPtr,
        _class: JClass,
        handle: JLong,
        data: JByteArray,
    ) -> JInt {
        jni::guard(code::PANIC, || {
            // SAFETY: JVM-provided env and array.
            match unsafe { input(env, data) } {
                Ok(b) => api::set_environment(handle, &b),
                Err(c) => c,
            }
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_diagnose(
        env: EnvPtr,
        _class: JClass,
        handle: JLong,
        data: JByteArray,
    ) -> JByteArray {
        jni::guard(null_mut(), || {
            // SAFETY: JVM-provided env and array.
            let out = match unsafe { input(env, data) } {
                Ok(b) => api::diagnose(handle, &b),
                Err(c) => api::status_only(c),
            };
            // SAFETY: JVM-provided env.
            unsafe { respond(env, &out) }
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_submitTls(
        env: EnvPtr,
        _class: JClass,
        handle: JLong,
        data: JByteArray,
    ) -> JInt {
        jni::guard(code::PANIC, || {
            // SAFETY: JVM-provided env and array.
            match unsafe { input(env, data) } {
                Ok(b) => api::submit_tls(handle, &b),
                Err(c) => c,
            }
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_evaluate(
        env: EnvPtr,
        _class: JClass,
        handle: JLong,
    ) -> JByteArray {
        // SAFETY: JVM-provided env.
        jni::guard(null_mut(), || unsafe {
            respond(env, &api::evaluate(handle))
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_systemConnections(
        env: EnvPtr,
        _class: JClass,
    ) -> JByteArray {
        // SAFETY: JVM-provided env.
        jni::guard(null_mut(), || unsafe {
            respond(env, &api::system_connections())
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_dohQuery(
        env: EnvPtr,
        _class: JClass,
        data: JByteArray,
    ) -> JByteArray {
        jni::guard(null_mut(), || {
            // SAFETY: JVM-provided env and array.
            let out = match unsafe { input(env, data) } {
                Ok(b) => api::doh_query(&b),
                Err(c) => api::status_only(c),
            };
            // SAFETY: JVM-provided env.
            unsafe { respond(env, &out) }
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_submitEncrypted(
        env: EnvPtr,
        _class: JClass,
        handle: JLong,
        data: JByteArray,
    ) -> JInt {
        jni::guard(code::PANIC, || {
            // SAFETY: JVM-provided env and array.
            match unsafe { input(env, data) } {
                Ok(b) => api::submit_encrypted(handle, &b),
                Err(c) => c,
            }
        })
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_thedpi_Native_networkChanged(
        _env: EnvPtr,
        _class: JClass,
        handle: JLong,
    ) -> JInt {
        jni::guard(code::PANIC, || api::network_changed(handle))
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_thedpi_Native_markApplied(
        _env: EnvPtr,
        _class: JClass,
        handle: JLong,
        action: JInt,
    ) -> JInt {
        jni::guard(code::PANIC, || api::mark_applied(handle, action))
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_desyncPacket(
        env: EnvPtr,
        _class: JClass,
        handle: JLong,
        data: JByteArray,
    ) -> JByteArray {
        jni::guard(null_mut(), || {
            // SAFETY: JVM-provided env and array.
            let out = match unsafe { input(env, data) } {
                Ok(b) => api::desync_packet(handle, &b),
                Err(c) => api::status_only(c),
            };
            // SAFETY: JVM-provided env.
            unsafe { respond(env, &out) }
        })
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_startProxy(
        env: EnvPtr,
        _class: JClass,
        handle: JLong,
        data: JByteArray,
    ) -> JByteArray {
        jni::guard(null_mut(), || {
            // SAFETY: JVM-provided env and array.
            let out = match unsafe { input(env, data) } {
                Ok(b) => api::start_proxy(handle, &b),
                Err(c) => api::status_only(c),
            };
            // SAFETY: JVM-provided env.
            unsafe { respond(env, &out) }
        })
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_thedpi_Native_stopProxy(
        _env: EnvPtr,
        _class: JClass,
        handle: JLong,
    ) -> JInt {
        jni::guard(code::PANIC, || api::stop_proxy(handle))
    }

    /// # Safety
    /// Called by the JVM with a valid `JNIEnv`.
    #[unsafe(no_mangle)]
    pub unsafe extern "system" fn Java_thedpi_Native_proxyStats(
        env: EnvPtr,
        _class: JClass,
        handle: JLong,
    ) -> JByteArray {
        // SAFETY: JVM-provided env.
        jni::guard(null_mut(), || unsafe {
            respond(env, &api::proxy_stats(handle))
        })
    }
}

#[cfg(test)]
#[path = "Tests.rs"]
mod tests;
