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

/// Fast ASCII lower-casing used on the DNS/target name-normalization path. The hot
/// implementation is hand-written SIMD Assembly; every other target uses the standard
/// library. Only bytes 'A'..'Z' (all < 0x80) are modified, so UTF-8 stays valid.
pub mod ascii {
    #[cfg(target_arch = "x86_64")]
    unsafe extern "sysv64" {
        fn the_dpi_ascii_lowercase(dst: *mut u8, src: *const u8, len: usize);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe extern "C" {
        fn the_dpi_ascii_lowercase(dst: *mut u8, src: *const u8, len: usize);
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
    pub mod decision {
        pub const STATE: u8 = 1;
        pub const ACTION: u8 = 2;
        pub const CONFIDENCE: u8 = 3;
        pub const CATEGORY: u8 = 4;
        pub const COOLDOWN_MS: u8 = 5;
        pub const PARAM: u8 = 6;
        pub const HIGH_IMPACT: u8 = 7;
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
    const KIND_INT: u8 = 1;
    const KIND_TEXT: u8 = 2;
    const KIND_RECORD: u8 = 3;
    const FIELD_HEADER: usize = 6;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Value {
        Int(i64),
        Text(String),
        Record(Record),
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
        let only_nxdomain = !d.observations.is_empty()
            && d.observations
                .iter()
                .all(|o| o.code == crate::intel::Obs::DnsNameError);
        if d.category == Category::DnsResolutionFailure && only_nxdomain {
            return Action::CheckTargetName;
        }
        action_for(d.category)
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
        r.int(t::SCORE, score.unwrap_or(-1))
            .int(t::EWMA, decider.ewma().unwrap_or(-1))
            .int(t::GENERATION, i64::from(generation))
            .int(t::STABILITY, decider.stability())
            .int(t::EVALUATIONS, i64::from(evaluations));
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
}

#[cfg(test)]
#[path = "Tests.rs"]
mod tests;
