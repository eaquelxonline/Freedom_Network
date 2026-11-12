//! THE DPI native core tests (Rust built-in test harness only).
//!
//! Network tests use loopback-only fake servers created by the test itself;
//! no external host is contacted.

use super::*;
use crate::decide::{Action, Decider, State};
use crate::intel::{Category, Diagnosis, Environment, Obs};
use crate::probe::{Outcome, ProbeConfig, RunReport, Status, TargetReport};
use crate::wire::{Record, WireError};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Serialises tests that use the global engine registry.
static REGISTRY_LOCK: Mutex<()> = Mutex::new(());

fn registry_guard() -> std::sync::MutexGuard<'static, ()> {
    REGISTRY_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Deterministic pseudo-random generator for fuzz-style tests (xorshift64*).
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 56) as u8).collect()
    }
}

// ---------------------------------------------------------------- wire

#[test]
fn wire_roundtrip_all_kinds() {
    let mut inner = Record::new();
    inner.int(1, -5).text(2, "çğıöşü ✓");
    let mut r = Record::with_status(0);
    r.int(1, i64::MAX)
        .int(1, i64::MIN)
        .text(2, "")
        .text(3, "hello")
        .record(4, inner.clone())
        .record(4, Record::new());
    let bytes = wire::encode(&r).unwrap();
    assert_eq!(&bytes[..3], b"DP\x01");
    let back = wire::decode(&bytes).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.status(), Some(0));
    assert_eq!(back.ints(1).collect::<Vec<_>>(), vec![i64::MAX, i64::MIN]);
    assert_eq!(back.records(4).count(), 2);
    assert_eq!(
        back.records(4).next().unwrap().get_text(2),
        Some("çğıöşü ✓")
    );
}

#[test]
fn wire_rejects_malformed_input() {
    assert_eq!(wire::decode(b""), Err(WireError::Truncated));
    assert_eq!(wire::decode(b"XX\x01"), Err(WireError::BadMagic));
    assert_eq!(wire::decode(b"DP\x02"), Err(WireError::BadVersion));
    assert_eq!(
        wire::decode(b"DP\x01\x00\x01\x00"),
        Err(WireError::Truncated)
    );
    assert_eq!(
        wire::decode(b"DP\x01\x00\x01\x00\x00\x00\x08\x00"),
        Err(WireError::Truncated)
    );
    assert_eq!(
        wire::decode(b"DP\x01\x00\x01\x00\x00\x00\x02\x00\x00"),
        Err(WireError::BadLength)
    );
    assert_eq!(
        wire::decode(b"DP\x01\x00\x09\x00\x00\x00\x00"),
        Err(WireError::BadKind)
    );
    assert_eq!(
        wire::decode(b"DP\x01\x00\x02\x00\x00\x00\x02\xff\xfe"),
        Err(WireError::BadUtf8)
    );
    assert_eq!(
        wire::decode(b"DP\x01\x00\x01\xff\xff\xff\xff"),
        Err(WireError::Truncated)
    );
    assert_eq!(
        wire::decode(&vec![0u8; wire::MAX_MESSAGE + 1]),
        Err(WireError::TooLarge)
    );
    // Nesting beyond MAX_DEPTH.
    let mut r = Record::new();
    for _ in 0..wire::MAX_DEPTH {
        let mut outer = Record::new();
        outer.record(1, r);
        r = outer;
    }
    assert_eq!(wire::encode(&r), Err(WireError::TooDeep));
    let mut raw = b"DP\x01".to_vec();
    let mut nested: Vec<u8> = Vec::new();
    for _ in 0..wire::MAX_DEPTH + 1 {
        let mut f = vec![1u8, 3];
        f.extend_from_slice(&(nested.len() as u32).to_be_bytes());
        f.extend_from_slice(&nested);
        nested = f;
    }
    raw.extend_from_slice(&nested);
    assert_eq!(wire::decode(&raw), Err(WireError::TooDeep));
}

#[test]
fn wire_field_count_limit() {
    let mut raw = b"DP\x01".to_vec();
    for _ in 0..=wire::MAX_FIELDS {
        raw.extend_from_slice(&[1, 2, 0, 0, 0, 0]);
    }
    assert_eq!(wire::decode(&raw), Err(WireError::TooManyFields));
}

#[test]
fn wire_text_truncates_on_char_boundary() {
    let s = "ş".repeat(wire::MAX_TEXT); // 2 bytes each
    let mut r = Record::new();
    r.text(1, &s);
    let t = r.get_text(1).unwrap();
    assert!(t.len() <= wire::MAX_TEXT);
    assert!(t.chars().all(|c| c == 'ş'));
    assert_eq!(wire::truncate_utf8("aş", 2), "a");
}

#[test]
fn wire_fuzz_never_panics() {
    let mut rng = Lcg(0x5EED);
    let mut valid = Record::with_status(0);
    valid.text(1, "x").record(2, Record::with_status(3));
    let good = wire::encode(&valid).unwrap();
    for cut in 0..good.len() {
        let _ = wire::decode(&good[..cut]);
    }
    for _ in 0..5000 {
        let n = (rng.next() % 96) as usize;
        let mut b = rng.bytes(n);
        if rng.next().is_multiple_of(2) && b.len() >= 3 {
            b[..3].copy_from_slice(b"DP\x01");
        }
        let _ = wire::decode(&b);
    }
}

// ---------------------------------------------------------------- dns

#[test]
fn hostname_validation() {
    for ok in [
        "example.com",
        "a.b-c.d",
        "xn--bcher-kva.example",
        "localhost",
        "svc.test.",
        "a1.b2",
    ] {
        assert!(dns::is_valid_hostname(ok), "{ok}");
    }
    let long_label = format!("{}.com", "a".repeat(64));
    let long_name = vec!["a".repeat(63); 5].join(".");
    for bad in [
        "",
        ".",
        "-a.com",
        "a-.com",
        "a..b",
        "a_b.com",
        "1.2.3.4",
        "exa mple.com",
        "ü.com",
        &long_label,
        &long_name,
    ] {
        assert!(!dns::is_valid_hostname(bad), "{bad}");
    }
}

#[test]
fn query_wire_format() {
    let q = dns::build_query(0xBEEF, "Example.COM", dns::TYPE_AAAA, true).unwrap();
    assert_eq!(&q[..12], &[0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    assert_eq!(&q[12..25], b"\x07Example\x03COM\x00");
    assert_eq!(&q[25..29], &[0, 28, 0, 1]);
    assert_eq!(&q[29..], &[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]); // OPT, 1232
    let plain = dns::build_query(1, "a.b", dns::TYPE_A, false).unwrap();
    assert_eq!(plain.len(), 12 + 5 + 4);
    assert!(dns::build_query(1, &vec!["a".repeat(63); 4].join("."), dns::TYPE_A, false).is_err());
    assert!(dns::build_query(1, "a..b", dns::TYPE_A, false).is_err());
}

/// Builds a response to `query` with the given answers (rtype, rdata) using a
/// compression pointer to the question name.
fn make_response(query: &[u8], flags: u16, answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let (_, qend) = dns::read_name(query, 12).unwrap();
    let question = &query[12..qend + 4];
    let mut r = Vec::new();
    r.extend_from_slice(&query[..2]);
    r.extend_from_slice(&flags.to_be_bytes());
    r.extend_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(question);
    for (t, data) in answers {
        r.extend_from_slice(&[0xC0, 0x0C]);
        r.extend_from_slice(&t.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&300u32.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(data);
    }
    r
}

fn https_rdata() -> Vec<u8> {
    let mut d = vec![0, 1, 0]; // priority 1, target "."
    d.extend_from_slice(&[0, 1, 0, 6, 2, b'h', b'3', 2, b'h', b'2']); // alpn
    d.extend_from_slice(&[0, 3, 0, 2, 0x01, 0xBB]); // port 443
    d.extend_from_slice(&[0, 4, 0, 4, 192, 0, 2, 1]); // ipv4hint
    d.extend_from_slice(&[0, 5, 0, 3, 0xAA, 0xBB, 0xCC]); // ech (opaque)
    d
}

#[test]
fn parse_response_records() {
    let q = dns::build_query(7, "svc.test", dns::TYPE_A, true).unwrap();
    let mut cname = vec![3, b'w', b'w', b'w', 0xC0, 0x0C];
    let resp = make_response(
        &q,
        0x8180,
        &[
            (dns::TYPE_CNAME, std::mem::take(&mut cname)),
            (dns::TYPE_A, vec![10, 0, 0, 1]),
            (99, vec![1, 2]),
        ],
    );
    let r = dns::parse_response(&resp, 7, "SVC.test.", dns::TYPE_A).unwrap();
    assert_eq!(r.header.rcode(), 0);
    assert_eq!(r.answers.len(), 3);
    assert_eq!(r.answers[0].data, dns::RData::Cname("www.svc.test".into()));
    assert_eq!(r.answers[1].data, dns::RData::A(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(r.answers[1].name, "svc.test");
    assert_eq!(r.answers[1].ttl, 300);
    assert_eq!(r.answers[2].data, dns::RData::Other);

    let q6 = dns::build_query(9, "svc.test", dns::TYPE_AAAA, true).unwrap();
    let resp6 = make_response(
        &q6,
        0x8180,
        &[(dns::TYPE_AAAA, Ipv6Addr::LOCALHOST.octets().to_vec())],
    );
    let r6 = dns::parse_response(&resp6, 9, "svc.test", dns::TYPE_AAAA).unwrap();
    assert_eq!(r6.answers[0].data, dns::RData::Aaaa(Ipv6Addr::LOCALHOST));
}

#[test]
fn parse_https_svcb() {
    let q = dns::build_query(1, "svc.test", dns::TYPE_HTTPS, true).unwrap();
    let resp = make_response(&q, 0x8180, &[(dns::TYPE_HTTPS, https_rdata())]);
    let r = dns::parse_response(&resp, 1, "svc.test", dns::TYPE_HTTPS).unwrap();
    let dns::RData::Https(s) = &r.answers[0].data else {
        panic!("not https")
    };
    assert_eq!(s.priority, 1);
    assert_eq!(s.target, ".");
    assert_eq!(s.alpn, vec!["h3", "h2"]);
    assert_eq!(s.port, Some(443));
    assert!(s.ech);
    assert_eq!(s.ipv4_hints, vec![Ipv4Addr::new(192, 0, 2, 1)]);
}

#[test]
fn svcb_rejects_invalid_params() {
    // keys out of order
    assert!(dns::parse_svcb(&[0, 1, 0, 0, 3, 0, 2, 1, 187, 0, 1, 0, 3, 2, b'h', b'2']).is_err());
    // empty alpn id
    assert!(dns::parse_svcb(&[0, 1, 0, 0, 1, 0, 1, 0]).is_err());
    // compressed target name is forbidden
    assert!(dns::parse_svcb(&[0, 1, 0xC0, 0x0C]).is_err());
    // value length past end
    assert!(dns::parse_svcb(&[0, 1, 0, 0, 5, 0, 9, 1]).is_err());
    // port with wrong length
    assert!(dns::parse_svcb(&[0, 1, 0, 0, 3, 0, 1, 1]).is_err());
    // no-default-alpn must be empty
    assert!(dns::parse_svcb(&[0, 1, 0, 0, 2, 0, 1, 1]).is_err());
    // valid alias mode with unknown key
    assert!(dns::parse_svcb(&[0, 0, 0, 0x20, 0x00, 0, 0]).is_ok());
}

#[test]
fn parse_response_validation() {
    let q = dns::build_query(42, "svc.test", dns::TYPE_A, true).unwrap();
    let ok = make_response(&q, 0x8180, &[(dns::TYPE_A, vec![1, 2, 3, 4])]);
    assert_eq!(
        dns::parse_response(&ok, 43, "svc.test", dns::TYPE_A),
        Err(dns::DnsError::IdMismatch)
    );
    assert_eq!(
        dns::parse_response(&ok, 42, "other.test", dns::TYPE_A),
        Err(dns::DnsError::QuestionMismatch)
    );
    assert_eq!(
        dns::parse_response(&ok, 42, "svc.test", dns::TYPE_AAAA),
        Err(dns::DnsError::QuestionMismatch)
    );
    let mut not_resp = ok.clone();
    not_resp[2] &= 0x7F;
    assert_eq!(
        dns::parse_response(&not_resp, 42, "svc.test", dns::TYPE_A),
        Err(dns::DnsError::NotResponse)
    );
    let bad_a = make_response(&q, 0x8180, &[(dns::TYPE_A, vec![1, 2, 3])]);
    assert_eq!(
        dns::parse_response(&bad_a, 42, "svc.test", dns::TYPE_A),
        Err(dns::DnsError::BadRdata)
    );
    // Truncated (TC) responses carry no answers but are accepted.
    let tc = make_response(&q, 0x8380, &[]);
    let r = dns::parse_response(&tc, 42, "svc.test", dns::TYPE_A).unwrap();
    assert!(r.header.truncated());
    // FORMERR without question section.
    let mut formerr = vec![0, 42, 0x81, 0x81];
    formerr.extend_from_slice(&[0; 8]);
    assert_eq!(
        dns::parse_response(&formerr, 42, "svc.test", dns::TYPE_A)
            .unwrap()
            .header
            .rcode(),
        1
    );
    // Every truncation of a valid response fails cleanly.
    for cut in 0..ok.len() {
        assert!(dns::parse_response(&ok[..cut], 42, "svc.test", dns::TYPE_A).is_err());
    }
}

#[test]
fn name_compression_attacks_are_rejected() {
    // Self-pointer at offset 12.
    let mut m = vec![0u8; 12];
    m.extend_from_slice(&[0xC0, 12]);
    assert_eq!(dns::read_name(&m, 12), Err(dns::DnsError::PointerLoop));
    // Forward pointer.
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&[0xC0, 20, 0, 0, 0, 0, 0, 0, 1, b'a', 0]);
    assert_eq!(dns::read_name(&f, 12), Err(dns::DnsError::PointerLoop));
    // Backward loop: label "a" at 12 followed by pointer back to 12.
    let mut l = vec![0u8; 12];
    l.extend_from_slice(&[1, b'a', 0xC0, 12]);
    assert!(dns::read_name(&l, 12).is_err());
    // Reserved label types 0x40/0x80.
    let mut r = vec![0u8; 12];
    r.extend_from_slice(&[0x40, 0]);
    assert_eq!(dns::read_name(&r, 12), Err(dns::DnsError::BadName));
    // Over-long name via many labels.
    let mut big = vec![0u8; 12];
    for _ in 0..70 {
        big.extend_from_slice(&[3, b'a', b'b', b'c']);
    }
    big.push(0);
    assert_eq!(dns::read_name(&big, 12), Err(dns::DnsError::NameTooLong));
    // Non-printable octets are escaped, not passed through.
    let mut e = vec![0u8; 12];
    e.extend_from_slice(&[2, 0x00, b'.', 0]);
    assert_eq!(dns::read_name(&e, 12).unwrap().0, "\\000\\046");
}

#[test]
fn dns_parser_fuzz_never_panics() {
    let mut rng = Lcg(0xD1E5);
    let q = dns::build_query(5, "svc.test", dns::TYPE_HTTPS, true).unwrap();
    let base = make_response(
        &q,
        0x8180,
        &[
            (dns::TYPE_HTTPS, https_rdata()),
            (dns::TYPE_A, vec![1, 1, 1, 1]),
        ],
    );
    for _ in 0..20_000 {
        let mut m = base.clone();
        for _ in 0..(rng.next() % 6 + 1) {
            let i = (rng.next() as usize) % m.len();
            m[i] = (rng.next() >> 56) as u8;
        }
        let _ = dns::parse_response(&m, 5, "svc.test", dns::TYPE_HTTPS);
        let n = (rng.next() % 64) as usize;
        let _ = dns::parse_svcb(&rng.bytes(n));
    }
}

// ---------------------------------------------------------------- ascii (Assembly)

#[test]
fn asm_ascii_lowercase_matches_std_for_all_lengths() {
    let mut rng = Lcg(0x0A5C11);
    for len in 0..300usize {
        let src: Vec<u8> = (0..len).map(|_| (rng.next() >> 56) as u8).collect();
        let mut got = src.clone();
        crate::ascii::lowercase_in_place(&mut got);
        let mut want = src.clone();
        want.make_ascii_lowercase();
        assert_eq!(got, want, "len {len}");
    }
}

#[test]
fn asm_ascii_lowercase_full_byte_range_and_boundaries() {
    // Every byte value, including 'A'-1='@', 'Z'+1='[', and all high bytes >= 0x80.
    let mut got: Vec<u8> = (0u8..=255).collect();
    let mut want = got.clone();
    crate::ascii::lowercase_in_place(&mut got);
    want.make_ascii_lowercase();
    assert_eq!(got, want);
    assert_eq!(got[b'@' as usize], b'@');
    assert_eq!(got[b'A' as usize], b'a');
    assert_eq!(got[b'Z' as usize], b'z');
    assert_eq!(got[b'[' as usize], b'[');
    assert_eq!(got[0xC7], 0xC7); // high byte unchanged
}

#[test]
fn asm_ascii_lowercased_preserves_utf8() {
    for s in [
        "",
        "A",
        "Example.COM",
        "WWW.Türkçe-ÇŞİ.Example.COM.",
        &"ABCdef012-".repeat(40),
    ] {
        let mut want = s.as_bytes().to_vec();
        want.make_ascii_lowercase();
        assert_eq!(crate::ascii::lowercased(s).as_bytes(), &want[..], "{s}");
    }
    // The normalization path actually uses it.
    assert_eq!(
        probe::parse_target("WWW.Example.COM.").unwrap().host,
        "www.example.com"
    );
}

// ---------------------------------------------------------------- quic

fn vn_packet(dcid: &[u8], scid: &[u8], versions: &[u32]) -> Vec<u8> {
    let mut p = vec![0x80 | 0x2A, 0, 0, 0, 0, dcid.len() as u8];
    p.extend_from_slice(dcid);
    p.push(scid.len() as u8);
    p.extend_from_slice(scid);
    for v in versions {
        p.extend_from_slice(&v.to_be_bytes());
    }
    p
}

#[test]
fn quic_probe_layout() {
    let d = [1u8; 8];
    let s = [2u8; 8];
    let p = quic::build_probe(&d, &s, 10);
    assert_eq!(p.len(), quic::MIN_INITIAL_DATAGRAM);
    assert_eq!(p[0], 0xC0);
    assert_eq!(&p[1..5], &quic::GREASE_VERSION.to_be_bytes());
    let v = quic::GREASE_VERSION.to_be_bytes();
    assert!(
        v.iter().all(|b| b & 0x0F == 0x0A),
        "reserved 0x?a?a?a?a pattern"
    );
    assert_eq!(p[5], 8);
    assert_eq!(&p[6..14], &d);
    assert_eq!(p[14], 8);
    assert_eq!(&p[15..23], &s);
    assert_eq!(quic::build_probe(&d, &s, 1400).len(), 1400);
}

#[test]
fn quic_version_negotiation_parsing() {
    let (d, s) = ([1u8; 8], [2u8; 8]);
    let ok = vn_packet(&s, &d, &[quic::VERSION_1, quic::VERSION_2]);
    assert_eq!(
        quic::parse_version_negotiation(&ok, &d, &s),
        Ok(vec![quic::VERSION_1, quic::VERSION_2])
    );
    assert_eq!(
        quic::parse_version_negotiation(&vn_packet(&d, &s, &[1]), &d, &s),
        Err(quic::VnError::CidMismatch)
    );
    assert_eq!(
        quic::parse_version_negotiation(&vn_packet(&s, &d, &[]), &d, &s),
        Err(quic::VnError::Empty)
    );
    let mut not_vn = ok.clone();
    not_vn[4] = 1;
    assert_eq!(
        quic::parse_version_negotiation(&not_vn, &d, &s),
        Err(quic::VnError::NotVersionNegotiation)
    );
    let mut short = ok.clone();
    short[0] = 0x40;
    assert_eq!(
        quic::parse_version_negotiation(&short, &d, &s),
        Err(quic::VnError::NotLongHeader)
    );
    let mut odd = ok.clone();
    odd.push(0);
    assert_eq!(
        quic::parse_version_negotiation(&odd, &d, &s),
        Err(quic::VnError::Empty)
    );
    for cut in 0..ok.len() - 4 {
        assert!(quic::parse_version_negotiation(&ok[..cut], &d, &s).is_err());
    }
    let mut rng = Lcg(0x0BAD);
    for _ in 0..5000 {
        let n = (rng.next() % 64) as usize;
        let _ = quic::parse_version_negotiation(&rng.bytes(n), &d, &s);
    }
}

// ---------------------------------------------------------------- target parsing

#[test]
fn target_and_server_parsing() {
    let t = probe::parse_target("Example.COM").unwrap();
    assert_eq!(
        (t.host.as_str(), t.port, t.literal),
        ("example.com", 443, None)
    );
    assert_eq!(probe::parse_target("example.com:8443").unwrap().port, 8443);
    assert_eq!(
        probe::parse_target("example.com.").unwrap().host,
        "example.com"
    );
    let v4 = probe::parse_target("192.0.2.1:80").unwrap();
    assert_eq!(
        (v4.port, v4.literal),
        (80, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))))
    );
    assert_eq!(probe::parse_target("2001:db8::1").unwrap().port, 443);
    assert_eq!(probe::parse_target("[2001:db8::1]:853").unwrap().port, 853);
    assert_eq!(probe::parse_target("[2001:db8::1]").unwrap().port, 443);
    for bad in [
        "",
        "   ",
        "exa mple",
        "a.com:0",
        "a.com:99999",
        "a.com:x",
        "http://a.com",
        "1.2.3.4:0",
        "-a.com",
    ] {
        assert!(probe::parse_target(bad).is_none(), "{bad}");
    }
    assert_eq!(
        probe::parse_server("1.1.1.1"),
        Some("1.1.1.1:53".parse().unwrap())
    );
    assert_eq!(
        probe::parse_server("127.0.0.1:5353"),
        Some("127.0.0.1:5353".parse().unwrap())
    );
    assert_eq!(
        probe::parse_server("2001:db8::53"),
        Some("[2001:db8::53]:53".parse().unwrap())
    );
    assert_eq!(
        probe::parse_server("[2001:db8::53]:5353").unwrap().port(),
        5353
    );
    let scoped = probe::parse_server("fe80::1%3").unwrap();
    let SocketAddr::V6(v6) = scoped else { panic!() };
    assert_eq!(v6.scope_id(), 3);
    assert!(probe::parse_server("dns.example").is_none());
    assert!(probe::parse_server("1.1.1.1:0").is_none());
}

// ---------------------------------------------------------------- MTU search logic

#[test]
fn mtu_search_converges() {
    let (lo, hi) = (1228u32, 1500u32);
    for threshold in (lo..=hi).step_by(7) {
        let mut seen = Vec::new();
        let (found, probes, aborted) = probe::search_mtu(lo, hi, 7, |s| {
            seen.push(s);
            if s <= threshold {
                Outcome::Delivered
            } else {
                Outcome::Lost
            }
        });
        assert!(!aborted);
        assert!(
            found <= threshold,
            "never over-estimates: {found} > {threshold}"
        );
        assert!(
            threshold - found <= 8 || probes == 7,
            "threshold {threshold} found {found}"
        );
        assert!(probes <= 7);
    }
    assert_eq!(
        probe::search_mtu(1228, 1500, 7, |_| Outcome::Delivered),
        (1500, 1, false)
    );
    assert_eq!(
        probe::search_mtu(1228, 1500, 7, |_| Outcome::Failed),
        (1228, 1, true)
    );
    assert_eq!(
        probe::search_mtu(1500, 1500, 7, |_| Outcome::Lost),
        (1500, 0, false)
    );
    let (f, _, _) = probe::search_mtu(1228, 1500, 7, |s| {
        if s <= 1400 {
            Outcome::Delivered
        } else {
            Outcome::LocalLimit
        }
    });
    assert!((1392..=1400).contains(&f));
}

// ---------------------------------------------------------------- loopback fake servers

#[derive(Clone, Copy, PartialEq, Eq)]
enum DnsMode {
    Normal,
    Truncate,
    SpoofFirst,
    NxDomain,
    ServFail,
    Refused,
    Silent,
    Delay(u64),
}

struct FakeDns {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    queries: Arc<AtomicU32>,
    handles: Vec<thread::JoinHandle<()>>,
}

impl Drop for FakeDns {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for h in self.handles.drain(..) {
            let _ = h.join();
        }
    }
}

fn answer_for(query: &[u8], mode: DnsMode, tcp: bool) -> Option<Vec<u8>> {
    let (_, qend) = dns::read_name(query, 12).ok()?;
    let qtype = u16::from_be_bytes([query[qend], query[qend + 1]]);
    let answers: Vec<(u16, Vec<u8>)> = match qtype {
        dns::TYPE_A => vec![(dns::TYPE_A, vec![127, 0, 0, 1])],
        dns::TYPE_AAAA => vec![],
        dns::TYPE_HTTPS => vec![(dns::TYPE_HTTPS, https_rdata())],
        _ => vec![],
    };
    Some(match mode {
        DnsMode::Truncate if !tcp => make_response(query, 0x8380, &[]),
        DnsMode::NxDomain => make_response(query, 0x8183, &[]),
        DnsMode::ServFail => make_response(query, 0x8182, &[]),
        DnsMode::Refused => make_response(query, 0x8185, &[]),
        _ => make_response(query, 0x8180, &answers),
    })
}

fn fake_dns(mode: DnsMode) -> FakeDns {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(addr).unwrap();
    tcp.set_nonblocking(true).unwrap();
    udp.set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let queries = Arc::new(AtomicU32::new(0));
    let (s1, q1) = (stop.clone(), queries.clone());
    let h1 = thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while !s1.load(Ordering::SeqCst) {
            let Ok((n, from)) = udp.recv_from(&mut buf) else {
                continue;
            };
            q1.fetch_add(1, Ordering::SeqCst);
            match mode {
                DnsMode::Silent => continue,
                DnsMode::Delay(ms) => thread::sleep(Duration::from_millis(ms)),
                DnsMode::SpoofFirst => {
                    if let Some(mut bad) = answer_for(&buf[..n], mode, false) {
                        bad[0] ^= 0xFF; // wrong ID: must be ignored by the client
                        let _ = udp.send_to(&bad, from);
                    }
                }
                _ => {}
            }
            if let Some(r) = answer_for(&buf[..n], mode, false) {
                let _ = udp.send_to(&r, from);
            }
        }
    });
    let s2 = stop.clone();
    let h2 = thread::spawn(move || {
        while !s2.load(Ordering::SeqCst) {
            let Ok((mut c, _)) = tcp.accept() else {
                thread::sleep(Duration::from_millis(10));
                continue;
            };
            let _ = c.set_nonblocking(false);
            let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
            let mut len = [0u8; 2];
            if c.read_exact(&mut len).is_err() {
                continue;
            }
            let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
            if c.read_exact(&mut q).is_err() {
                continue;
            }
            if let Some(r) = answer_for(&q, mode, true) {
                let mut out = (r.len() as u16).to_be_bytes().to_vec();
                out.extend_from_slice(&r);
                let _ = c.write_all(&out);
            }
        }
    });
    FakeDns {
        addr,
        stop,
        queries,
        handles: vec![h1, h2],
    }
}

/// Fake QUIC endpoint answering Version Negotiation for datagrams ≤ `max_ip_size`.
fn fake_quic(max_ip_size: usize) -> (SocketAddr, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = s.local_addr().unwrap();
    s.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    let h = thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while !st.load(Ordering::SeqCst) {
            let Ok((n, from)) = s.recv_from(&mut buf) else {
                continue;
            };
            if n + 28 > max_ip_size || n < 23 {
                continue; // emulate a path that drops larger packets
            }
            let dcid = &buf[6..14];
            let scid = &buf[15..23];
            let _ = s.send_to(
                &vn_packet(scid, dcid, &[quic::VERSION_1, quic::VERSION_2]),
                from,
            );
        }
    });
    (addr, stop, h)
}

/// Loopback TCP endpoint that accepts and immediately closes connections, so the
/// kernel accept queue never fills during long benchmarks (which would turn later
/// probes into timeouts and measure the fixture instead of the engine).
fn tcp_sink() -> (u16, Arc<AtomicBool>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    l.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let st = stop.clone();
    thread::spawn(move || {
        while !st.load(Ordering::SeqCst) {
            match l.accept() {
                Ok((c, _)) => drop(c),
                Err(_) => thread::sleep(Duration::from_millis(1)),
            }
        }
    });
    (port, stop)
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

#[test]
fn dns_exchange_against_fake_server() {
    let srv = fake_dns(DnsMode::Normal);
    let a = probe::dns_exchange(srv.addr, "svc.test", dns::TYPE_A, Duration::from_secs(2)).unwrap();
    assert!(!a.via_tcp);
    assert_eq!(
        a.response.answers[0].data,
        dns::RData::A(Ipv4Addr::LOCALHOST)
    );
    let t =
        probe::dns_exchange_tcp(srv.addr, "svc.test", dns::TYPE_A, Duration::from_secs(2)).unwrap();
    assert!(t.via_tcp);
}

#[test]
fn dns_truncation_falls_back_to_tcp() {
    let srv = fake_dns(DnsMode::Truncate);
    let a = probe::dns_exchange(srv.addr, "svc.test", dns::TYPE_A, Duration::from_secs(2)).unwrap();
    assert!(a.via_tcp);
    assert_eq!(a.response.answers.len(), 1);
}

#[test]
fn dns_ignores_spoofed_responses() {
    let srv = fake_dns(DnsMode::SpoofFirst);
    let a = probe::dns_exchange(srv.addr, "svc.test", dns::TYPE_A, Duration::from_secs(2)).unwrap();
    assert_eq!(
        a.response.answers[0].data,
        dns::RData::A(Ipv4Addr::LOCALHOST)
    );
}

#[test]
fn dns_timeout_is_bounded() {
    let srv = fake_dns(DnsMode::Silent);
    let start = Instant::now();
    let r = probe::dns_exchange(
        srv.addr,
        "svc.test",
        dns::TYPE_A,
        Duration::from_millis(200),
    );
    assert_eq!(r.unwrap_err(), Status::Timeout);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn resolve_statuses() {
    let t = probe::parse_target("svc.test").unwrap();
    let ok = fake_dns(DnsMode::Normal);
    let r = probe::resolve(&t, &[ok.addr], Duration::from_secs(2), deadline());
    assert_eq!(r.status, Status::Ok);
    assert_eq!(r.v4, vec![Ipv4Addr::LOCALHOST]);
    assert!(r.https.as_ref().unwrap().alpn.contains(&"h3".to_string()));
    assert_eq!(r.server, Some(ok.addr));

    let nx = fake_dns(DnsMode::NxDomain);
    assert_eq!(
        probe::resolve(&t, &[nx.addr], Duration::from_secs(2), deadline()).status,
        Status::NameError
    );
    let sf = fake_dns(DnsMode::ServFail);
    assert_eq!(
        probe::resolve(&t, &[sf.addr], Duration::from_secs(2), deadline()).status,
        Status::ServerFailure
    );
    // REFUSED from the first resolver falls through to the next one.
    let refused = fake_dns(DnsMode::Refused);
    let r2 = probe::resolve(
        &t,
        &[refused.addr, ok.addr],
        Duration::from_secs(2),
        deadline(),
    );
    assert_eq!((r2.status, r2.server), (Status::Ok, Some(ok.addr)));
    assert_eq!(
        probe::resolve(&t, &[refused.addr], Duration::from_secs(2), deadline()).status,
        Status::Refused
    );
    assert_eq!(
        probe::resolve(&t, &[], Duration::from_secs(2), deadline()).status,
        Status::Unsupported
    );
    let lit = probe::parse_target("127.0.0.1:80").unwrap();
    assert_eq!(
        probe::resolve(&lit, &[ok.addr], Duration::from_secs(2), deadline()).status,
        Status::Skipped
    );
}

#[test]
fn resolver_statistics() {
    let srv = fake_dns(DnsMode::Normal);
    let st = probe::measure_resolver(
        srv.addr,
        false,
        "svc.test",
        4,
        Duration::from_secs(1),
        deadline(),
    );
    assert_eq!(
        (st.sent, st.received, st.status, st.tcp_status),
        (4, 4, Status::Ok, Status::NotRun)
    );
    assert_eq!(st.loss_pct(), 0);
    assert!(srv.queries.load(Ordering::SeqCst) >= 4);
    let silent = fake_dns(DnsMode::Silent);
    let s2 = probe::measure_resolver(
        silent.addr,
        false,
        "svc.test",
        2,
        Duration::from_millis(150),
        deadline(),
    );
    assert_eq!((s2.received, s2.status), (0, Status::Timeout));
    assert_eq!(s2.loss_pct(), 100);
    assert_eq!(
        s2.tcp_status,
        Status::Ok,
        "silent UDP but TCP answers → TCP fallback measured"
    );
}

#[test]
fn jitter_and_average() {
    let st = probe::ResolverStats {
        server: "127.0.0.1:53".parse().unwrap(),
        alternate: false,
        sent: 4,
        received: 4,
        rtt_us: vec![10_000, 30_000, 10_000, 30_000],
        status: Status::Ok,
        tcp_status: Status::NotRun,
    };
    assert_eq!(st.avg_us(), 20_000);
    assert_eq!(st.jitter_us(), 20_000);
}

#[test]
fn tcp_probe_open_and_closed() {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let r = probe::tcp_probe(addr, 3, Duration::from_secs(1), deadline());
    assert_eq!((r.status, r.attempts, r.successes), (Status::Ok, 3, 3));
    drop(l);
    let closed = probe::tcp_probe(addr, 2, Duration::from_secs(1), deadline());
    assert_eq!((closed.status, closed.successes), (Status::Refused, 0));
    let expired = probe::tcp_probe(addr, 2, Duration::from_secs(1), Instant::now());
    assert_eq!((expired.status, expired.attempts), (Status::Skipped, 0));
}

#[test]
fn quic_probe_against_fake_endpoint() {
    let (addr, stop, h) = fake_quic(1500);
    let r = probe::quic_probe(addr, Duration::from_secs(1), 2, deadline());
    assert_eq!(r.status, Status::Ok);
    assert!(r.supports_v1());
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    // Nothing listening: ICMP port unreachable (Refused) or Timeout, never Ok.
    let r2 = probe::quic_probe(addr, Duration::from_millis(200), 1, deadline());
    assert!(
        matches!(r2.status, Status::Refused | Status::Timeout),
        "{:?}",
        r2.status
    );
}

#[test]
fn path_mtu_probe_finds_size_dependent_drop() {
    let (addr, stop, h) = fake_quic(1400);
    let r = probe::mtu_probe(addr, 1500, Duration::from_millis(400), deadline());
    stop.store(true, Ordering::SeqCst);
    h.join().unwrap();
    assert_eq!(r.status, Status::Ok, "{r:?}");
    assert_eq!(r.ceiling, 1500);
    assert!((1392..=1400).contains(&r.path_mtu), "{r:?}");
    let (addr2, stop2, h2) = fake_quic(1500);
    let full = probe::mtu_probe(addr2, 1500, Duration::from_millis(400), deadline());
    stop2.store(true, Ordering::SeqCst);
    h2.join().unwrap();
    assert_eq!(
        (full.status, full.path_mtu, full.probes),
        (Status::Ok, 1500, 2)
    );
}

#[test]
fn full_run_is_bounded_and_ordered() {
    let srv = fake_dns(DnsMode::Normal);
    let (port, _sink) = tcp_sink();
    let targets: Vec<_> = ["svc.test", "other.test", "127.0.0.1"]
        .iter()
        .map(|h| probe::parse_target(&format!("{h}:{port}")).unwrap())
        .collect();
    let cfg = ProbeConfig {
        timeout: Duration::from_millis(500),
        dns_samples: 3,
        mtu: false,
        ..ProbeConfig::default()
    };
    let run = probe::run(&cfg, &[srv.addr], &[srv.addr], &targets, 1500);
    assert_eq!(run.targets.len(), 3);
    assert_eq!(
        run.targets
            .iter()
            .map(|t| t.target.host.as_str())
            .collect::<Vec<_>>(),
        vec!["svc.test", "other.test", "127.0.0.1"]
    );
    assert_eq!(run.resolvers.len(), 2);
    assert!(!run.resolvers[0].alternate && run.resolvers[1].alternate);
    assert!(run.targets.iter().all(|t| t.tcp4.successes > 0));
    assert!(run.duration_us < 20_000_000);
    // Budget exhaustion: nothing runs after the deadline.
    let tight = ProbeConfig {
        budget: Duration::from_millis(0),
        ..cfg
    };
    let r = probe::run(&tight, &[srv.addr], &[], &targets, 1500);
    assert!(r.targets.iter().all(|t| t.tcp4.attempts == 0));
}

// ---------------------------------------------------------------- classification

fn healthy_target(host: &str) -> TargetReport {
    let mut t = TargetReport {
        target: probe::parse_target(host).unwrap(),
        ..TargetReport::default()
    };
    t.dns.status = Status::Ok;
    t.dns.v4 = vec![Ipv4Addr::new(192, 0, 2, 10)];
    t.tcp4 = probe::TcpResult {
        status: Status::Ok,
        address: None,
        attempts: 3,
        successes: 3,
        median_us: 25_000,
    };
    t.tls.status = probe::TLS_OK;
    t.tls.version = "TLSv1.3".into();
    t.tls.alpn = "h2".into();
    t
}

fn resolver(ok: bool, alternate: bool) -> probe::ResolverStats {
    probe::ResolverStats {
        server: if alternate {
            "192.0.2.53:53"
        } else {
            "198.51.100.53:53"
        }
        .parse()
        .unwrap(),
        alternate,
        sent: 5,
        received: if ok { 5 } else { 0 },
        rtt_us: if ok { vec![20_000; 5] } else { vec![] },
        status: if ok { Status::Ok } else { Status::Timeout },
        tcp_status: Status::NotRun,
    }
}

fn run_of(targets: Vec<TargetReport>, resolvers: Vec<probe::ResolverStats>) -> RunReport {
    RunReport {
        resolvers,
        targets,
        duration_us: 1_000_000,
        ..RunReport::default()
    }
}

fn env_with(f: impl FnOnce(&mut Environment)) -> Environment {
    let mut e = Environment {
        connected: intel::YES,
        validated: intel::YES,
        has_ipv6: intel::YES,
        dns_servers: vec!["198.51.100.53".into()],
        ..Environment::default()
    };
    f(&mut e);
    e
}

fn top(d: &[Diagnosis]) -> Category {
    d.first().map_or(Category::None, |x| x.category)
}

fn has(d: &[Diagnosis], c: Category) -> Option<&Diagnosis> {
    d.iter().find(|x| x.category == c)
}

#[test]
fn classify_healthy_network() {
    let run = run_of(
        vec![healthy_target("a.test"), healthy_target("b.test")],
        vec![resolver(true, false)],
    );
    let d = intel::classify(Some(&env_with(|_| {})), &run);
    assert_eq!(top(&d), Category::NoProblemDetected);
    assert!(d[0].confidence >= 80);
    assert!(
        d[0].observations
            .iter()
            .all(|o| o.code == Obs::TargetHealthy)
    );
}

#[test]
fn classify_not_connected_short_circuits() {
    let run = run_of(vec![healthy_target("a.test")], vec![]);
    let d = intel::classify(Some(&env_with(|e| e.connected = intel::NO)), &run);
    assert_eq!(top(&d), Category::LocalNetworkInterruption);
    assert_eq!(d.len(), 1);
}

#[test]
fn classify_no_targets_is_insufficient_evidence() {
    let d = intel::classify(None, &RunReport::default());
    assert_eq!(top(&d), Category::InsufficientEvidence);
}

#[test]
fn classify_ipv6_path_failure() {
    let mut t = healthy_target("a.test");
    t.dns.v6 = vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)];
    t.tcp6 = probe::TcpResult {
        status: Status::Timeout,
        address: None,
        attempts: 3,
        successes: 0,
        median_us: 0,
    };
    let run = run_of(vec![t], vec![resolver(true, false)]);
    let d = intel::classify(Some(&env_with(|_| {})), &run);
    assert_eq!(top(&d), Category::Ipv6ConnectivityFailure);
    assert_eq!(d[0].confidence, 75);
    // Without a global IPv6 address it is only an advisory, not a failure.
    let d2 = intel::classify(Some(&env_with(|e| e.has_ipv6 = intel::NO)), &run);
    assert!(has(&d2, Category::Ipv6ConnectivityFailure).is_none());
    assert_eq!(top(&d2), Category::NoProblemDetected);
}

#[test]
fn classify_ipv4_path_failure() {
    let mut t = healthy_target("a.test");
    t.tcp4 = probe::TcpResult {
        status: Status::Unreachable,
        address: None,
        attempts: 3,
        successes: 0,
        median_us: 0,
    };
    t.dns.v6 = vec![Ipv6Addr::LOCALHOST];
    t.tcp6 = probe::TcpResult {
        status: Status::Ok,
        address: None,
        attempts: 3,
        successes: 3,
        median_us: 30_000,
    };
    let d = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![t], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d), Category::Ipv4ConnectivityFailure);
}

#[test]
fn classify_dns_failures() {
    let mut nx = healthy_target("typo.test");
    nx.dns.status = Status::NameError;
    let d = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![nx], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d), Category::DnsResolutionFailure);
    assert_eq!(d[0].observations[0].code, Obs::DnsNameError);

    // All resolvers silent on UDP but TCP works → UDP availability issue.
    let mut t = healthy_target("a.test");
    t.dns.status = Status::Timeout;
    let mut r = resolver(false, false);
    r.tcp_status = Status::Ok;
    let d2 = intel::classify(Some(&env_with(|_| {})), &run_of(vec![t.clone()], vec![r]));
    assert_eq!(top(&d2), Category::UdpAvailabilityIssue);

    // Silent resolver, platform says validated → DNS timeout with high confidence.
    let d3 = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![t.clone()], vec![resolver(false, false)]),
    );
    assert_eq!(top(&d3), Category::DnsTimeout);
    assert_eq!(d3[0].confidence, 80);

    // A user-authorized alternate resolver that answered everything raises confidence.
    let d4 = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![t], vec![resolver(false, false), resolver(true, true)]),
    );
    assert_eq!(d4[0].confidence, 90);
    assert!(
        d4[0]
            .observations
            .iter()
            .any(|o| o.code == Obs::AlternateResolverBetter)
    );
}

#[test]
fn classify_remote_vs_local_tcp_failure() {
    let mut bad = healthy_target("down.test");
    bad.tcp4 = probe::TcpResult {
        status: Status::Refused,
        address: None,
        attempts: 3,
        successes: 0,
        median_us: 0,
    };
    bad.tls = probe::TlsObservation::default();
    let d = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(
            vec![bad.clone(), healthy_target("up.test")],
            vec![resolver(true, false)],
        ),
    );
    assert_eq!(top(&d), Category::RemoteServiceFailure);
    let mut bad2 = bad.clone();
    bad2.target.host = "down2.test".into();
    let d2 = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![bad, bad2], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d2), Category::TcpConnectionFailure);
}

#[test]
fn classify_tls_and_captive_portal() {
    let mut t = healthy_target("a.test");
    t.tls.status = probe::TLS_CERTIFICATE;
    let d = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![t.clone()], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d), Category::CertificateValidationFailure);
    assert!(has(&d, Category::CaptivePortal).is_none());
    let d2 = intel::classify(
        Some(&env_with(|e| e.validated = intel::NO)),
        &run_of(vec![t.clone()], vec![resolver(true, false)]),
    );
    assert!(has(&d2, Category::CaptivePortal).is_some());
    let d3 = intel::classify(
        Some(&env_with(|e| e.captive = intel::YES)),
        &run_of(vec![healthy_target("a.test")], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d3), Category::CaptivePortal);
    t.tls.status = probe::TLS_HANDSHAKE;
    let d4 = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![t], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d4), Category::TlsNegotiationFailure);
}

#[test]
fn classify_quic_http3_and_mtu() {
    let mut t = healthy_target("a.test");
    t.dns.https = Some(dns::Svcb {
        priority: 1,
        alpn: vec!["h3".into(), "h2".into()],
        ..dns::Svcb::default()
    });
    t.quic.status = Status::Timeout;
    let d = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![t.clone()], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d), Category::QuicIncompatibility);
    // No h3 advertised → a silent UDP endpoint proves nothing.
    let mut no_h3 = t.clone();
    no_h3.dns.https = None;
    let d0 = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![no_h3], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d0), Category::NoProblemDetected);
    t.quic = probe::QuicResult {
        status: Status::Ok,
        rtt_us: 1,
        versions: vec![quic::VERSION_2],
    };
    let d2 = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![t.clone()], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d2), Category::Http3Incompatibility);
    t.quic.versions = vec![quic::VERSION_1];
    t.mtu = probe::MtuResult {
        status: Status::Ok,
        path_mtu: 1400,
        ceiling: 1500,
        probes: 5,
    };
    t.tls.status = probe::TLS_TIMEOUT;
    let d3 = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![t], vec![resolver(true, false)]),
    );
    let m = has(&d3, Category::MtuRelatedFailure).unwrap();
    assert_eq!(m.confidence, 70);
    assert_eq!(m.observations[0].args, vec![1400, 1500]);
}

#[test]
fn platform_blocked_probes_are_not_misdiagnosed() {
    // Android 17 blocks local-network sockets without ACCESS_LOCAL_NETWORK: that is a
    // platform policy, not a TCP failure, so no specific cause may be claimed.
    let mut t = healthy_target("192.168.1.10");
    t.dns.status = Status::Skipped;
    t.tcp4 = probe::TcpResult {
        status: Status::Blocked,
        address: None,
        attempts: 3,
        successes: 0,
        median_us: 0,
    };
    t.tls = probe::TlsObservation::default();
    let d = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(
            vec![t, healthy_target("a.test")],
            vec![resolver(true, false)],
        ),
    );
    assert!(
        has(&d, Category::RemoteServiceFailure).is_none()
            && has(&d, Category::TcpConnectionFailure).is_none()
    );
    assert!(
        has(&d, Category::Advisory)
            .unwrap()
            .observations
            .iter()
            .any(|o| o.code == Obs::PlatformBlocked)
    );
    let mut r = resolver(false, false);
    r.status = Status::Blocked;
    let mut nt = healthy_target("a.test");
    nt.dns.status = Status::Blocked;
    let d2 = intel::classify(Some(&env_with(|_| {})), &run_of(vec![nt], vec![r]));
    assert!(has(&d2, Category::DnsTimeout).is_none());
    assert_eq!(
        probe::status_from_io(&std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        Status::Blocked
    );
}

#[test]
fn classify_advisories_do_not_mask_health() {
    let env = env_with(|e| {
        e.os_name = "Windows".into();
        e.os_build = 19045;
        e.metered = intel::YES;
    });
    let d = intel::classify(
        Some(&env),
        &run_of(vec![healthy_target("a.test")], vec![resolver(true, false)]),
    );
    assert_eq!(top(&d), Category::NoProblemDetected);
    let adv = has(&d, Category::Advisory).unwrap();
    assert!(
        adv.observations
            .iter()
            .any(|o| o.code == Obs::Windows10EndOfSupport)
    );
    assert_eq!(d.last().unwrap().category, Category::Advisory);
    let win11 = env_with(|e| {
        e.os_name = "Windows".into();
        e.os_build = 26100;
    });
    let d2 = intel::classify(
        Some(&win11),
        &run_of(vec![healthy_target("a.test")], vec![resolver(true, false)]),
    );
    assert!(has(&d2, Category::Advisory).is_none());
}

#[test]
fn classification_is_deterministic() {
    let mut t = healthy_target("a.test");
    t.tls.status = probe::TLS_HANDSHAKE;
    let run = run_of(
        vec![t, healthy_target("b.test")],
        vec![resolver(true, false)],
    );
    let env = env_with(|_| {});
    let first = intel::classify(Some(&env), &run);
    for _ in 0..50 {
        assert_eq!(intel::classify(Some(&env), &run), first);
    }
}

// ---------------------------------------------------------------- decision engine

fn diag(c: Category, conf: u8) -> Vec<Diagnosis> {
    vec![Diagnosis {
        category: c,
        confidence: conf,
        observations: vec![],
    }]
}

#[test]
fn single_evaluation_never_triggers_high_impact_change() {
    let mut d = Decider::new(60_000, 10);
    let x = d.step(0, Some(500), &diag(Category::DnsTimeout, 95));
    assert_eq!((x.state, x.action), (State::Pending, Action::KeepCurrent));
    assert_eq!(x.param, Action::UseAlternateDns as i64);
    let y = d.step(1000, Some(500), &diag(Category::DnsTimeout, 95));
    assert_eq!(
        (y.state, y.action),
        (State::Recommend, Action::UseAlternateDns)
    );
    assert!(y.action.is_high_impact());
}

#[test]
fn low_confidence_requires_more_evidence() {
    let mut d = Decider::new(0, 10);
    let x = d.step(0, Some(500), &diag(Category::DnsTimeout, 40));
    assert_eq!(
        (x.state, x.action),
        (State::NeedMoreEvidence, Action::CollectMoreEvidence)
    );
    let y = d.step(0, Some(500), &diag(Category::Ipv6ConnectivityFailure, 60)); // high impact needs 70
    assert_eq!(y.state, State::NeedMoreEvidence);
    let z = d.step(0, Some(500), &diag(Category::InsufficientEvidence, 90));
    assert_eq!(z.state, State::NeedMoreEvidence);
}

#[test]
fn instant_low_impact_recommendation() {
    let mut d = Decider::new(60_000, 10);
    let x = d.step(0, Some(400), &diag(Category::CaptivePortal, 90));
    assert_eq!(
        (x.state, x.action),
        (State::Recommend, Action::OpenCaptivePortal)
    );
    let mut d2 = Decider::new(60_000, 10);
    let y = d2.step(0, Some(400), &diag(Category::TlsNegotiationFailure, 70));
    assert_eq!(y.state, State::Pending);
}

#[test]
fn cooldown_blocks_rapid_switching() {
    let mut d = Decider::new(60_000, 10);
    d.step(0, Some(500), &diag(Category::CaptivePortal, 95));
    // A different, stronger problem appears 5 s later.
    let a = d.step(5_000, Some(500), &diag(Category::QuicIncompatibility, 95));
    assert_eq!(
        (a.state, a.action),
        (State::CoolingDown, Action::OpenCaptivePortal)
    );
    assert_eq!(a.cooldown_remaining_ms, 55_000);
    let b = d.step(61_000, Some(500), &diag(Category::QuicIncompatibility, 95));
    assert_eq!(
        (b.state, b.action),
        (State::Recommend, Action::PreferTcpFallback)
    );
}

#[test]
fn hysteresis_keeps_current_recommendation() {
    let mut d = Decider::new(0, 10);
    d.step(0, Some(500), &diag(Category::CaptivePortal, 90));
    let both = vec![
        Diagnosis {
            category: Category::CaptivePortal,
            confidence: 90,
            observations: vec![],
        },
        Diagnosis {
            category: Category::QuicIncompatibility,
            confidence: 95,
            observations: vec![],
        },
    ];
    // 95 < 90 + 10 while the original problem persists → keep.
    for t in 1..5 {
        let x = d.step(t * 1000, Some(500), &both);
        assert_eq!(x.action, Action::OpenCaptivePortal);
    }
}

#[test]
fn recovery_returns_to_keep_current_after_debounce() {
    let mut d = Decider::new(60_000, 10);
    d.step(0, Some(300), &diag(Category::CaptivePortal, 95));
    let a = d.step(1000, Some(900), &diag(Category::NoProblemDetected, 80));
    assert_eq!(
        (a.state, a.action),
        (State::Pending, Action::OpenCaptivePortal)
    );
    let b = d.step(2000, Some(900), &diag(Category::NoProblemDetected, 80));
    assert_eq!((b.state, b.action), (State::Stable, Action::KeepCurrent));
}

#[test]
fn verification_confirms_successful_change() {
    let mut d = Decider::new(0, 10);
    d.step(0, Some(400), &diag(Category::DnsTimeout, 90));
    d.step(1, Some(400), &diag(Category::DnsTimeout, 90));
    assert_eq!(d.current(), Action::UseAlternateDns);
    assert!(d.mark_applied(Action::UseAlternateDns));
    let v = d.step(2, Some(900), &diag(Category::NoProblemDetected, 80));
    assert_eq!(
        (v.state, v.action),
        (State::Verifying, Action::UseAlternateDns)
    );
    let c = d.step(3, Some(900), &diag(Category::NoProblemDetected, 80));
    assert_eq!(
        (c.state, c.action, c.param),
        (
            State::Confirmed,
            Action::KeepCurrent,
            Action::UseAlternateDns as i64
        )
    );
}

#[test]
fn verification_rejects_and_rolls_back() {
    let mut d = Decider::new(0, 10);
    d.step(0, Some(600), &diag(Category::Ipv6ConnectivityFailure, 80));
    d.step(1, Some(600), &diag(Category::Ipv6ConnectivityFailure, 80));
    assert!(d.mark_applied(Action::PreferIpv4));
    d.step(2, Some(200), &diag(Category::Ipv6ConnectivityFailure, 80));
    let r = d.step(3, Some(200), &diag(Category::Ipv6ConnectivityFailure, 80));
    assert_eq!(
        (r.state, r.action, r.param),
        (
            State::Rejected,
            Action::RevertLastChange,
            Action::PreferIpv4 as i64
        )
    );
}

#[test]
fn mark_applied_requires_baseline_and_real_action() {
    let mut d = Decider::new(0, 10);
    assert!(!d.mark_applied(Action::UseAlternateDns), "no score yet");
    d.step(0, Some(500), &diag(Category::NoProblemDetected, 80));
    assert!(!d.mark_applied(Action::KeepCurrent));
    assert!(d.mark_applied(Action::LowerMtu));
}

#[test]
fn network_change_resets_state() {
    let mut d = Decider::new(60_000, 10);
    d.step(0, Some(500), &diag(Category::CaptivePortal, 95));
    d.network_changed();
    assert_eq!(d.current(), Action::KeepCurrent);
    assert_eq!(d.ewma(), None);
    let x = d.step(1, Some(500), &diag(Category::QuicIncompatibility, 95));
    assert_eq!(
        x.action,
        Action::PreferTcpFallback,
        "no cooldown carried over from the old network"
    );
}

#[test]
fn ewma_and_stability() {
    let mut d = Decider::new(0, 10);
    d.step(0, Some(800), &[]);
    d.step(0, Some(400), &[]);
    assert_eq!(d.ewma(), Some(700));
    let mut s = Decider::new(0, 10);
    for _ in 0..8 {
        s.step(0, Some(500), &[]);
    }
    assert_eq!(s.stability(), 1000);
}

#[test]
fn nxdomain_only_evidence_suggests_checking_the_name() {
    let mut nx = healthy_target("typo.test");
    nx.dns.status = Status::NameError;
    let run = run_of(
        vec![nx, healthy_target("ok.test")],
        vec![resolver(true, false)],
    );
    let d = intel::classify(Some(&env_with(|_| {})), &run);
    assert_eq!(decide::action_for_diagnosis(&d[0]), Action::CheckTargetName);
    assert!(!Action::CheckTargetName.is_high_impact());
    let mut dec = Decider::new(0, 10);
    dec.step(0, Some(800), &d);
    assert_eq!(dec.step(1, Some(800), &d).action, Action::CheckTargetName);
    // SERVFAIL evidence still points at the resolver.
    let mut sf = healthy_target("a.test");
    sf.dns.status = Status::ServerFailure;
    let d2 = intel::classify(
        Some(&env_with(|_| {})),
        &run_of(vec![sf], vec![resolver(true, false)]),
    );
    assert_eq!(
        decide::action_for_diagnosis(&d2[0]),
        Action::UseAlternateDns
    );
}

#[test]
fn every_category_maps_to_an_action() {
    for c in 0..=17i64 {
        let cat: Category = unsafe_free_category(c);
        let a = decide::action_for(cat);
        assert!(decide::Action::from_code(a as i64).is_some());
    }
    assert!(decide::Action::from_code(13).is_some());
    assert!(decide::Action::from_code(14).is_none());
    assert!(decide::Action::from_code(-1).is_none());
}

fn unsafe_free_category(c: i64) -> Category {
    use Category::*;
    [
        None,
        DnsResolutionFailure,
        DnsTimeout,
        Ipv4ConnectivityFailure,
        Ipv6ConnectivityFailure,
        TcpConnectionFailure,
        UdpAvailabilityIssue,
        TlsNegotiationFailure,
        CertificateValidationFailure,
        QuicIncompatibility,
        Http3Incompatibility,
        MtuRelatedFailure,
        CaptivePortal,
        LocalNetworkInterruption,
        RemoteServiceFailure,
        InsufficientEvidence,
        NoProblemDetected,
        Advisory,
    ][c as usize]
}

// ---------------------------------------------------------------- scoring

#[test]
fn score_bounds_and_ordering() {
    let good = run_of(vec![healthy_target("a.test")], vec![resolver(true, false)]);
    let s_good = engine::score(&good).unwrap();
    assert!((0..=1000).contains(&s_good));
    let mut bad_t = healthy_target("a.test");
    bad_t.tcp4.successes = 0;
    bad_t.tls.status = probe::TLS_TIMEOUT;
    let bad = run_of(vec![bad_t], vec![resolver(false, false)]);
    let s_bad = engine::score(&bad).unwrap();
    assert!(s_bad < s_good, "{s_bad} < {s_good}");
    assert!(s_bad >= 0);
    assert_eq!(engine::score(&RunReport::default()), None);
    assert_eq!(engine::score(&good), Some(s_good));
}

// ---------------------------------------------------------------- encrypted DNS (DoH3/DoH)

#[test]
fn wire_bytes_roundtrip_and_limits() {
    let mut r = Record::new();
    r.bytes(1, &[0, 1, 2, 0xFF, 0x80])
        .bytes(1, &[])
        .text(2, "x");
    let back = wire::decode(&wire::encode(&r).unwrap()).unwrap();
    assert_eq!(back, r);
    assert_eq!(back.get_bytes(1), Some(&[0u8, 1, 2, 0xFF, 0x80][..]));
    let mut big = Record::new();
    big.bytes(1, &vec![7u8; wire::MAX_BYTES + 100]);
    assert_eq!(
        big.get_bytes(1).unwrap().len(),
        wire::MAX_BYTES,
        "truncated on build"
    );
    let mut raw = b"DP\x01\x01\x04".to_vec();
    raw.extend_from_slice(&((wire::MAX_BYTES + 1) as u32).to_be_bytes());
    raw.extend(std::iter::repeat_n(0u8, wire::MAX_BYTES + 1));
    assert_eq!(wire::decode(&raw), Err(WireError::BadLength));
}

fn doh_request(name: &str, qtype: u16) -> Vec<u8> {
    let mut r = Record::new();
    r.text(tags::doh_query::NAME, name)
        .int(tags::doh_query::QTYPE, i64::from(qtype));
    wire::encode(&r).unwrap()
}

#[test]
fn doh_query_is_rfc8484_wire_format_with_id_zero() {
    let out = wire::decode(&api::doh_query(&doh_request("Svc.Test", dns::TYPE_AAAA))).unwrap();
    assert_eq!(out.status(), Some(0));
    let q = out.get_bytes(tags::doh_query::QUERY).unwrap();
    assert_eq!(&q[..2], &[0, 0], "RFC 8484 §4.1: ID 0");
    assert_eq!(
        q,
        &dns::build_query(0, "Svc.Test", dns::TYPE_AAAA, true).unwrap()[..]
    );
    let bad = wire::decode(&api::doh_query(&doh_request("exa mple", 1))).unwrap();
    assert_eq!(bad.status(), Some(i64::from(code::INVALID_ARGUMENT)));
    assert_eq!(
        wire::decode(&api::doh_query(b"junk")).unwrap().status(),
        Some(i64::from(code::WIRE))
    );
}

#[test]
fn encrypted_answers_are_validated_by_the_hardened_parser() {
    let q = dns::build_query(0, "svc.test", dns::TYPE_A, true).unwrap();
    let ok = make_response(
        &q,
        0x8180,
        &[
            (dns::TYPE_A, vec![192, 0, 2, 7]),
            (dns::TYPE_A, vec![192, 0, 2, 8]),
        ],
    );
    assert_eq!(
        engine::validate_encrypted_answer(&ok, "svc.test", dns::TYPE_A),
        (Status::Ok, 2)
    );
    let nx = make_response(&q, 0x8183, &[]);
    assert_eq!(
        engine::validate_encrypted_answer(&nx, "svc.test", dns::TYPE_A),
        (Status::NameError, 0)
    );
    let empty = make_response(&q, 0x8180, &[]);
    assert_eq!(
        engine::validate_encrypted_answer(&empty, "svc.test", dns::TYPE_A),
        (Status::NoData, 0)
    );
    // A captive portal returning HTML with HTTP 200 must never count as a DNS answer.
    let html = b"<html><body>Please log in</body></html>";
    assert_eq!(
        engine::validate_encrypted_answer(html, "svc.test", dns::TYPE_A).0,
        Status::Invalid
    );
    // Wrong ID (non-zero) or another name are rejected too.
    let mut wrong_id = ok.clone();
    wrong_id[1] = 9;
    assert_eq!(
        engine::validate_encrypted_answer(&wrong_id, "svc.test", dns::TYPE_A).0,
        Status::Invalid
    );
    assert_eq!(
        engine::validate_encrypted_answer(&ok, "other.test", dns::TYPE_A).0,
        Status::Invalid
    );
}

fn enc(name: &str, status: Status, protocol: i64) -> probe::EncryptedResolver {
    probe::EncryptedResolver {
        endpoint: "https://doh.example/dns-query".into(),
        name: name.into(),
        protocol,
        status,
        rtt_us: 25_000,
        answers: u32::from(status == Status::Ok),
    }
}

#[test]
fn classify_with_encrypted_resolvers() {
    let env = env_with(|_| {});
    // 1) System DNS silent, DoH3 works: DNS diagnosis strengthened, recommendation = encrypted DNS.
    let mut t = healthy_target("a.test");
    t.dns.status = Status::Timeout;
    let mut run = run_of(vec![t], vec![resolver(false, false)]);
    run.encrypted
        .push(enc("a.test", Status::Ok, probe::ENC_DOH3));
    let d = intel::classify(Some(&env), &run);
    assert_eq!(top(&d), Category::DnsTimeout);
    assert_eq!(d[0].confidence, 90);
    assert!(
        d[0].observations
            .iter()
            .any(|o| o.code == Obs::EncryptedDnsResolved && o.args == vec![25, probe::ENC_DOH3])
    );
    assert_eq!(decide::action_for_diagnosis(&d[0]), Action::UseAlternateDns);

    // 2) Healthy network, no system encryption: privacy advisory only, no problem claimed.
    let mut run2 = run_of(vec![healthy_target("a.test")], vec![resolver(true, false)]);
    run2.encrypted
        .push(enc("a.test", Status::Ok, probe::ENC_DOH));
    let d2 = intel::classify(Some(&env), &run2);
    assert_eq!(top(&d2), Category::NoProblemDetected);
    assert!(
        has(&d2, Category::Advisory)
            .unwrap()
            .observations
            .iter()
            .any(|o| o.code == Obs::EncryptedDnsAvailable)
    );
    // ...but not when the platform already uses encrypted DNS.
    let d2b = intel::classify(Some(&env_with(|e| e.private_dns = intel::YES)), &run2);
    assert!(
        !d2b.iter()
            .flat_map(|x| &x.observations)
            .any(|o| o.code == Obs::EncryptedDnsAvailable)
    );

    // 3) System resolver says NXDOMAIN, independent encrypted resolver answers: discrepancy.
    let mut nx = healthy_target("blocked-name.test");
    nx.dns.status = Status::NameError;
    let mut run3 = run_of(
        vec![nx.clone(), healthy_target("ok.test")],
        vec![resolver(true, false)],
    );
    run3.encrypted
        .push(enc("blocked-name.test", Status::Ok, probe::ENC_DOH3));
    let d3 = intel::classify(Some(&env), &run3);
    let dd = has(&d3, Category::DnsResolutionFailure).unwrap();
    assert!(
        dd.observations
            .iter()
            .any(|o| o.code == Obs::ResolverDiscrepancy)
    );
    assert_eq!(decide::action_for_diagnosis(dd), Action::UseAlternateDns);

    // 4) Both say NXDOMAIN: corroborated name error -> check the name, not the resolver.
    let mut run4 = run_of(
        vec![nx, healthy_target("ok.test")],
        vec![resolver(true, false)],
    );
    run4.encrypted
        .push(enc("blocked-name.test", Status::NameError, probe::ENC_DOH));
    let d4 = intel::classify(Some(&env), &run4);
    let dd4 = has(&d4, Category::DnsResolutionFailure).unwrap();
    assert!(
        dd4.observations
            .iter()
            .any(|o| o.code == Obs::EncryptedDnsConfirmsNxdomain)
    );
    assert_eq!(decide::action_for_diagnosis(dd4), Action::CheckTargetName);

    // 5) Encrypted resolver unreachable: informational only, never a network failure.
    let mut run5 = run_of(vec![healthy_target("a.test")], vec![resolver(true, false)]);
    run5.encrypted
        .push(enc("a.test", Status::Timeout, probe::ENC_DOH3));
    let d5 = intel::classify(Some(&env), &run5);
    assert_eq!(top(&d5), Category::NoProblemDetected);
    assert!(
        has(&d5, Category::Advisory)
            .unwrap()
            .observations
            .iter()
            .any(|o| o.code == Obs::EncryptedDnsFailed)
    );
}

#[test]
fn engine_accepts_platform_doh_results() {
    let _g = registry_guard();
    let srv = fake_dns(DnsMode::Normal);
    let (port, _sink) = tcp_sink();
    let h = api::create(Some(&config_bytes(|r| {
        r.int(tags::config::QUIC, 0);
    })));
    api::set_environment(h, &env_bytes(&srv.addr.to_string()));
    assert_eq!(
        api::submit_encrypted(h, &wire::encode(&Record::new()).unwrap()),
        code::NO_DATA,
        "needs a run first"
    );
    let run = wire::decode(&api::diagnose(h, &request(&[format!("svc.test:{port}")]))).unwrap();
    assert_eq!(run.status(), Some(0));
    // Platform layer: build query natively, "send" over HTTPS, get the DoH answer back.
    let q = wire::decode(&api::doh_query(&doh_request("svc.test", dns::TYPE_A))).unwrap();
    let answer = make_response(
        q.get_bytes(tags::doh_query::QUERY).unwrap(),
        0x8180,
        &[(dns::TYPE_A, vec![192, 0, 2, 1])],
    );
    let mut res = Record::new();
    res.text(tags::enc::ENDPOINT, "https://doh.example/dns-query")
        .int(tags::enc::PROTOCOL, probe::ENC_DOH3)
        .int(tags::enc::TRANSPORT, Status::Ok.code())
        .int(tags::enc::RTT_US, 18_000)
        .text(tags::enc::QUERY_NAME, "svc.test")
        .int(tags::enc::QTYPE, i64::from(dns::TYPE_A))
        .bytes(tags::enc::RESPONSE, &answer);
    let mut sub = Record::new();
    sub.record(tags::enc_submit::RESULT, res);
    assert_eq!(
        api::submit_encrypted(h, &wire::encode(&sub).unwrap()),
        code::OK
    );
    let e = wire::decode(&api::evaluate(h)).unwrap();
    let advisory = e
        .records(tags::eval::DIAGNOSIS)
        .find(|d| d.get_int(tags::diagnosis::CATEGORY) == Some(Category::Advisory as i64))
        .expect("advisory");
    assert!(
        advisory
            .records(tags::diagnosis::OBSERVATION)
            .any(|o| o.get_int(tags::observation::CODE) == Some(Obs::EncryptedDnsAvailable as i64))
    );
    let mut missing = Record::new();
    missing.record(tags::enc_submit::RESULT, Record::new());
    assert_eq!(
        api::submit_encrypted(h, &wire::encode(&missing).unwrap()),
        code::INVALID_ARGUMENT
    );
    assert_eq!(
        api::submit_encrypted(-5, &wire::encode(&sub).unwrap()),
        code::INVALID_HANDLE
    );
    api::destroy(h);
}

// ---------------------------------------------------------------- system-wide connections

fn dword(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
fn port_dword(p: u16) -> [u8; 4] {
    let b = p.to_be_bytes();
    [b[0], b[1], 0, 0]
}

type Tcp4Row = (u32, [u8; 4], u16, [u8; 4], u16, u32);
type Tcp6Row = (u32, Ipv6Addr, u16, Ipv6Addr, u16, u32);

fn mib_tcp4(rows: &[Tcp4Row]) -> Vec<u8> {
    let mut v = dword(rows.len() as u32).to_vec();
    for (st, l, lp, r, rp, pid) in rows {
        v.extend(dword(*st));
        v.extend(l);
        v.extend(port_dword(*lp));
        v.extend(r);
        v.extend(port_dword(*rp));
        v.extend(dword(*pid));
    }
    v
}

fn mib_tcp6(rows: &[Tcp6Row]) -> Vec<u8> {
    let mut v = dword(rows.len() as u32).to_vec();
    for (st, l, lp, r, rp, pid) in rows {
        v.extend(l.octets());
        v.extend(dword(0));
        v.extend(port_dword(*lp));
        v.extend(r.octets());
        v.extend(dword(0));
        v.extend(port_dword(*rp));
        v.extend(dword(*st));
        v.extend(dword(*pid));
    }
    v
}

fn mib_udp4(rows: &[([u8; 4], u16, u32)]) -> Vec<u8> {
    let mut v = dword(rows.len() as u32).to_vec();
    for (l, lp, pid) in rows {
        v.extend(l);
        v.extend(port_dword(*lp));
        v.extend(dword(*pid));
    }
    v
}

#[test]
fn sysnet_parses_owner_pid_tables() {
    use crate::sysnet::{self, state};
    let t4 = mib_tcp4(&[
        (
            state::ESTABLISHED,
            [10, 0, 0, 2],
            50_000,
            [93, 184, 216, 34],
            443,
            1200,
        ),
        (state::LISTEN, [0, 0, 0, 0], 445, [0, 0, 0, 0], 0, 4),
    ]);
    let c = sysnet::parse_tcp4(&t4);
    assert_eq!(c.len(), 2);
    assert_eq!(c[0].local, "10.0.0.2:50000".parse().unwrap());
    assert_eq!(c[0].remote, Some("93.184.216.34:443".parse().unwrap()));
    assert_eq!(
        (c[0].state, c[0].pid, c[0].proto),
        (state::ESTABLISHED, 1200, sysnet::PROTO_TCP)
    );
    assert_eq!(c[1].remote, None, "listeners have no peer");
    let peer6: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let t6 = mib_tcp6(&[(state::SYN_SENT, Ipv6Addr::LOCALHOST, 60_000, peer6, 443, 77)]);
    let c6 = sysnet::parse_tcp6(&t6);
    assert_eq!(c6[0].remote, Some(SocketAddr::new(IpAddr::V6(peer6), 443)));
    assert_eq!((c6[0].state, c6[0].pid), (state::SYN_SENT, 77));
    let u = sysnet::parse_udp4(&mib_udp4(&[([0, 0, 0, 0], 5353, 900)]));
    assert_eq!(
        (u[0].proto, u[0].local.port(), u[0].pid),
        (sysnet::PROTO_UDP, 5353, 900)
    );
}

#[test]
fn sysnet_never_trusts_the_row_count() {
    use crate::sysnet;
    let mut t4 = mib_tcp4(&[(5, [1, 1, 1, 1], 1, [2, 2, 2, 2], 2, 3)]);
    t4[..4].copy_from_slice(&u32::MAX.to_le_bytes()); // claims 4 billion rows
    assert_eq!(sysnet::parse_tcp4(&t4).len(), 1);
    for cut in 0..t4.len() {
        let _ = sysnet::parse_tcp4(&t4[..cut]);
        let _ = sysnet::parse_tcp6(&t4[..cut]);
        let _ = sysnet::parse_udp4(&t4[..cut]);
        let _ = sysnet::parse_udp6(&t4[..cut]);
    }
    let mut rng = Lcg(0x5E7);
    for _ in 0..2000 {
        let n = (rng.next() % 200) as usize;
        let b = rng.bytes(n);
        let _ = sysnet::parse_tcp6(&b);
        let _ = sysnet::parse_udp6(&b);
    }
}

#[test]
fn sysnet_summary_and_findings() {
    use crate::sysnet::{self, state};
    let peer = |i: u8| [203, 0, 113, i];
    let mut rows = vec![
        (state::LISTEN, [0, 0, 0, 0], 3389, [0, 0, 0, 0], 0, 900),
        (
            state::ESTABLISHED,
            [127, 0, 0, 1],
            5000,
            [127, 0, 0, 1],
            5001,
            500,
        ), // loopback IPC
    ];
    for i in 0..4 {
        rows.push((
            state::SYN_SENT,
            [10, 0, 0, 2],
            40_000 + u16::from(i),
            peer(i),
            443,
            1200,
        ));
    }
    for i in 0..3 {
        rows.push((
            state::ESTABLISHED,
            [10, 0, 0, 2],
            41_000 + u16::from(i),
            peer(10 + i),
            443,
            1300,
        ));
    }
    for i in 0..25u16 {
        rows.push((
            state::CLOSE_WAIT,
            [10, 0, 0, 2],
            42_000 + i,
            peer(50),
            80,
            1400,
        ));
    }
    let mut conns = sysnet::parse_tcp4(&mib_tcp4(&rows));
    conns.extend(sysnet::parse_udp4(&mib_udp4(&[([0, 0, 0, 0], 53, 1300)])));
    let names = |pid: u32| match pid {
        1200 => Some("blocked-app.exe".to_string()),
        1300 => Some("browser.exe".to_string()),
        _ => None,
    };
    let s = sysnet::summarize(&conns, names);
    assert_eq!(
        (
            s.total,
            s.established,
            s.listen,
            s.syn_sent,
            s.close_wait,
            s.udp,
            s.exposed_listeners
        ),
        (35, 4, 1, 4, 25, 1, 1)
    );
    assert_eq!(
        s.processes[0].name, "blocked-app.exe",
        "stuck handshakes sort first"
    );
    assert_eq!(s.processes[0].remotes, 4);
    let browser = s.processes.iter().find(|p| p.pid == 1300).unwrap();
    assert_eq!(
        (
            browser.established,
            browser.udp,
            browser.remotes,
            browser.sample.len()
        ),
        (3, 1, 3, 3)
    );
    let ipc = s.processes.iter().find(|p| p.pid == 500).unwrap();
    assert_eq!(
        (ipc.name.as_str(), ipc.remotes),
        ("pid 500", 0),
        "loopback is not a remote endpoint"
    );
    let codes: Vec<i64> = s.findings.iter().map(|f| f.code).collect();
    assert!(
        codes.contains(&sysnet::F_STUCK_HANDSHAKES)
            && codes.contains(&sysnet::F_CLOSE_WAIT_LEAK)
            && codes.contains(&sysnet::F_EXPOSED_LISTENERS)
    );
    let stuck = s
        .findings
        .iter()
        .find(|f| f.code == sysnet::F_STUCK_HANDSHAKES)
        .unwrap();
    assert_eq!(
        (stuck.subject.as_str(), stuck.args.clone()),
        ("blocked-app.exe", vec![4, 1200])
    );
    let quiet = sysnet::summarize(&[], |_| None);
    assert_eq!(quiet.findings[0].code, sysnet::F_NO_ACTIVITY);
    let rec = wire::decode(&wire::encode(&sysnet::encode(&s)).unwrap()).unwrap();
    assert_eq!(rec.get_int(tags::sysnet::SYN_SENT), Some(4));
    assert_eq!(rec.records(tags::sysnet::FINDING).count(), 3);
}

#[test]
fn sysnet_live_snapshot() {
    #[cfg(not(windows))]
    assert_eq!(
        wire::decode(&api::system_connections()).unwrap().status(),
        Some(i64::from(code::UNSUPPORTED))
    );
    #[cfg(windows)]
    {
        // Open real sockets in this process and find them in the machine-wide table.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let _c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let _a = l.accept().unwrap();
        let rec = wire::decode(&api::system_connections()).unwrap();
        assert_eq!(rec.status(), Some(0), "{rec:?}");
        assert!(rec.get_int(tags::sysnet::LISTEN).unwrap() >= 1);
        assert!(rec.get_int(tags::sysnet::ESTABLISHED).unwrap() >= 2);
        // FFI + row layout: our exact sockets are decoded from the live table.
        let raw = crate::sys::win::connection_tables().unwrap();
        let rows = crate::sysnet::parse_tcp4(&raw.tcp4);
        let ours: Vec<_> = rows
            .iter()
            .filter(|c| c.local.port() == port || c.remote.map(|r| r.port()) == Some(port))
            .collect();
        assert!(
            ours.iter()
                .any(|c| c.state == crate::sysnet::state::LISTEN && c.remote.is_none())
        );
        assert_eq!(
            ours.iter()
                .filter(|c| c.state == crate::sysnet::state::ESTABLISHED)
                .count(),
            2
        );
        // Owner attribution: required whenever the OS reports owners at all (real Windows;
        // some emulators report PID 0 for every row).
        if rows.iter().any(|c| c.pid != 0) {
            let me = std::process::id();
            assert!(ours.iter().all(|c| c.pid == me), "{ours:?}");
            let mine = rec
                .records(tags::sysnet::PROCESS)
                .find(|p| p.get_int(tags::process::PID) == Some(i64::from(me)))
                .expect("own process listed");
            assert!(
                mine.get_text(tags::process::NAME)
                    .unwrap()
                    .ends_with(".exe")
            );
        }
    }
}

// ---------------------------------------------------------------- engine + api

fn config_bytes(f: impl FnOnce(&mut Record)) -> Vec<u8> {
    let mut r = Record::new();
    r.int(tags::config::TIMEOUT_MS, 400)
        .int(tags::config::DNS_SAMPLES, 2)
        .int(tags::config::MTU, 0)
        .int(tags::config::COOLDOWN_MS, 0);
    f(&mut r);
    wire::encode(&r).unwrap()
}

fn env_bytes(dns: &str) -> Vec<u8> {
    let mut e = Environment {
        connected: intel::YES,
        validated: intel::YES,
        has_ipv6: intel::NO,
        mtu: 1500,
        ..Environment::default()
    };
    e.dns_servers.push(dns.into());
    wire::encode(&e.to_record()).unwrap()
}

fn request(targets: &[String]) -> Vec<u8> {
    let mut r = Record::new();
    for t in targets {
        r.text(tags::request::TARGET, t);
    }
    wire::encode(&r).unwrap()
}

#[test]
fn config_is_clamped() {
    let mut r = Record::new();
    r.int(tags::config::TIMEOUT_MS, 1)
        .int(tags::config::DNS_SAMPLES, 999)
        .int(tags::config::MAX_PARALLEL, -3)
        .int(tags::config::HYSTERESIS_PCT, 90);
    let c = engine::Config::from_record(Some(&r));
    assert_eq!(c.probe.timeout, Duration::from_millis(100));
    assert_eq!(c.probe.dns_samples, 10);
    assert_eq!(c.probe.max_parallel, 4, "negative → default");
    assert_eq!(c.hysteresis_pct, 50);
    let d = engine::Config::from_record(None);
    assert_eq!(d.cooldown_ms, 60_000);
}

#[test]
fn environment_record_roundtrip() {
    let e = env_with(|e| {
        e.os_name = "Android".into();
        e.os_build = 37;
        e.gateways = vec!["192.168.1.1".into()];
        e.private_dns_name = "dns.example".into();
    });
    assert_eq!(Environment::from_record(&e.to_record()), e);
    let mut junk = Record::new();
    junk.int(tags::env::CAPTIVE, 77)
        .int(tags::env::MTU, 1 << 40)
        .int(tags::env::NETWORK_TYPE, 99);
    let j = Environment::from_record(&junk);
    assert_eq!(
        (j.captive, j.mtu, j.network_type),
        (intel::UNKNOWN, 0, intel::NET_UNKNOWN)
    );
}

#[test]
fn api_lifecycle_and_errors() {
    let _g = registry_guard();
    assert_eq!(API_VERSION, 1);
    let h = api::create(None);
    assert!(h > 0);
    assert_eq!(api::create(Some(b"garbage")), i64::from(code::WIRE));
    assert_eq!(api::set_environment(h, b"nope"), code::WIRE);
    assert_eq!(
        wire::decode(&api::diagnose(h, &request(&[])))
            .unwrap()
            .status(),
        Some(i64::from(code::NO_ENVIRONMENT))
    );
    assert_eq!(
        wire::decode(&api::evaluate(h)).unwrap().status(),
        Some(i64::from(code::NO_DATA))
    );
    assert_eq!(
        api::submit_tls(h, &wire::encode(&Record::new()).unwrap()),
        code::NO_DATA
    );
    assert_eq!(api::mark_applied(h, 3), code::NO_DATA);
    assert_eq!(api::mark_applied(h, 99), code::INVALID_ARGUMENT);
    assert_eq!(api::destroy(h), code::OK);
    assert_eq!(
        api::destroy(h),
        code::INVALID_HANDLE,
        "double destroy is safe"
    );
    for bad in [h, 0, -1, i64::MAX] {
        assert_eq!(
            api::set_environment(bad, &env_bytes("127.0.0.1")),
            code::INVALID_HANDLE
        );
        assert_eq!(api::network_changed(bad), code::INVALID_HANDLE);
        assert_eq!(
            wire::decode(&api::evaluate(bad)).unwrap().status(),
            Some(i64::from(code::INVALID_HANDLE))
        );
    }
    let h2 = api::create(None);
    assert!(h2 > h, "handles are never reused");
    api::destroy(h2);
    assert_eq!(
        wire::decode(&api::status_only(code::PANIC))
            .unwrap()
            .status(),
        Some(i64::from(code::PANIC))
    );
}

#[test]
fn api_engine_limit() {
    let _g = registry_guard();
    let mut made = Vec::new();
    loop {
        let h = api::create(None);
        if h < 0 {
            assert_eq!(h, i64::from(code::LIMIT));
            break;
        }
        made.push(h);
        assert!(made.len() <= api::MAX_ENGINES);
    }
    assert_eq!(api::engine_count(), api::MAX_ENGINES);
    for h in made {
        api::destroy(h);
    }
}

#[test]
fn api_rejects_invalid_requests() {
    let _g = registry_guard();
    let h = api::create(Some(&config_bytes(|_| {})));
    api::set_environment(h, &env_bytes("127.0.0.1:9"));
    let bad = wire::decode(&api::diagnose(h, &request(&["exa mple".into()]))).unwrap();
    assert_eq!(bad.status(), Some(i64::from(code::INVALID_ARGUMENT)));
    assert_eq!(bad.get_text(tags::run::INVALID), Some("exa mple"));
    let many: Vec<String> = (0..9).map(|i| format!("h{i}.test")).collect();
    assert_eq!(
        wire::decode(&api::diagnose(h, &request(&many)))
            .unwrap()
            .status(),
        Some(i64::from(code::LIMIT))
    );
    api::destroy(h);
}

#[test]
fn engine_end_to_end_on_loopback() {
    let _g = registry_guard();
    let srv = fake_dns(DnsMode::Normal);
    let (port, _sink) = tcp_sink();
    let h = api::create(Some(&config_bytes(|_| {})));
    assert_eq!(
        api::set_environment(h, &env_bytes(&srv.addr.to_string())),
        code::OK
    );
    let host = format!("svc.test:{port}");
    let run = wire::decode(&api::diagnose(h, &request(std::slice::from_ref(&host)))).unwrap();
    assert_eq!(run.status(), Some(0));
    let t = run.records(tags::run::TARGET).next().unwrap();
    assert_eq!(t.get_text(tags::target::HOST), Some("svc.test"));
    assert_eq!(t.get_int(tags::target::DNS_STATUS), Some(Status::Ok.code()));
    assert_eq!(
        t.get_int(tags::target::TCP4_STATUS),
        Some(Status::Ok.code())
    );
    assert!(t.texts(tags::target::ALPN).any(|a| a == "h3"));
    assert_eq!(t.get_int(tags::target::ECH), Some(1));
    assert_eq!(run.records(tags::run::RESOLVER).count(), 1);

    // TLS observation from the platform layer: certificate failure.
    let mut obs = Record::new();
    obs.int(tags::tls::PORT, i64::from(port))
        .text(tags::tls::HOST, "svc.test")
        .int(tags::tls::STATUS, probe::TLS_CERTIFICATE);
    let mut sub = Record::new();
    sub.record(tags::tls_submit::RESULT, obs);
    assert_eq!(api::submit_tls(h, &wire::encode(&sub).unwrap()), code::OK);

    let e1 = wire::decode(&api::evaluate(h)).unwrap();
    let d1 = e1.records(tags::eval::DIAGNOSIS).next().unwrap();
    assert_eq!(
        d1.get_int(tags::diagnosis::CATEGORY),
        Some(Category::CertificateValidationFailure as i64)
    );
    let dec1 = e1.records(tags::eval::DECISION).next().unwrap();
    assert_eq!(
        dec1.get_int(tags::decision::STATE),
        Some(State::Pending as i64)
    );
    let e2 = wire::decode(&api::evaluate(h)).unwrap();
    let dec2 = e2.records(tags::eval::DECISION).next().unwrap();
    assert_eq!(
        dec2.get_int(tags::decision::ACTION),
        Some(Action::CheckCertificateEnvironment as i64)
    );
    assert_eq!(e2.get_int(tags::eval::EVALUATIONS), Some(2));
    let score = e2.get_int(tags::eval::SCORE).unwrap();
    assert!((0..=1000).contains(&score));

    // Network change discards results tied to the previous network.
    assert_eq!(api::network_changed(h), code::OK);
    assert_eq!(
        wire::decode(&api::evaluate(h)).unwrap().status(),
        Some(i64::from(code::NO_DATA))
    );
    api::destroy(h);
}

#[test]
fn concurrent_diagnose_is_rejected_not_raced() {
    let _g = registry_guard();
    let srv = fake_dns(DnsMode::Delay(400));
    let h = api::create(Some(&config_bytes(|r| {
        r.int(tags::config::TIMEOUT_MS, 1500)
            .int(tags::config::DNS_SAMPLES, 1);
    })));
    api::set_environment(h, &env_bytes(&srv.addr.to_string()));
    let req = request(&["svc.test:9".into()]);
    let r2 = req.clone();
    let t = thread::spawn(move || wire::decode(&api::diagnose(h, &r2)).unwrap().status());
    thread::sleep(Duration::from_millis(100));
    let second = wire::decode(&api::diagnose(h, &req)).unwrap().status();
    let first = t.join().unwrap();
    assert_eq!(second, Some(i64::from(code::BUSY)));
    assert_eq!(first, Some(0));
    api::destroy(h);
}

#[test]
fn network_change_during_diagnose_discards_results() {
    let _g = registry_guard();
    let srv = fake_dns(DnsMode::Delay(300));
    let h = api::create(Some(&config_bytes(|r| {
        r.int(tags::config::TIMEOUT_MS, 1500)
            .int(tags::config::DNS_SAMPLES, 1);
    })));
    api::set_environment(h, &env_bytes(&srv.addr.to_string()));
    let req = request(&["svc.test:9".into()]);
    let t = thread::spawn(move || wire::decode(&api::diagnose(h, &req)).unwrap().status());
    thread::sleep(Duration::from_millis(100));
    api::network_changed(h);
    assert_eq!(t.join().unwrap(), Some(i64::from(code::NO_DATA)));
    api::destroy(h);
}

#[test]
fn concurrent_api_use_with_destroy_is_safe() {
    let _g = registry_guard();
    let h = api::create(None);
    let env = env_bytes("127.0.0.1:9");
    let workers: Vec<_> = (0..8)
        .map(|i| {
            let env = env.clone();
            thread::spawn(move || {
                for _ in 0..200 {
                    let _ = api::set_environment(h, &env);
                    let _ = api::evaluate(h);
                    let _ = api::network_changed(h);
                    if i == 0 {
                        let _ = api::destroy(h);
                    }
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert_eq!(api::destroy(h), code::INVALID_HANDLE);
}

#[test]
fn detect_environment_reports_platform() {
    let r = wire::decode(&api::detect_environment()).unwrap();
    assert_eq!(r.get_text(tags::env::ARCH), Some(std::env::consts::ARCH));
    #[cfg(not(windows))]
    assert_eq!(r.status(), Some(i64::from(code::UNSUPPORTED)));
    #[cfg(windows)]
    {
        assert_eq!(r.status(), Some(0));
        assert_eq!(r.get_text(tags::env::OS_NAME), Some("Windows"));
    }
}

#[test]
fn panics_are_contained_by_guard() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let v = jni::guard(-6, || -> i32 { panic!("boom") });
    std::panic::set_hook(prev);
    assert_eq!(v, -6);
    assert_eq!(jni::guard(0, || 5), 5);
}

#[test]
fn random_ids_vary() {
    let a: Vec<u64> = (0..64).map(|_| probe::random_u64()).collect();
    let mut b = a.clone();
    b.sort_unstable();
    b.dedup();
    assert_eq!(a.len(), b.len());
}

// ---------------------------------------------------------------- benchmarks & stress (run explicitly)
//
//   cargo test --release -- --ignored --nocapture --test-threads=1 bench_
//   cargo test --release -- --ignored --nocapture stress_

fn bench<F: FnMut()>(name: &str, iters: u32, mut f: F) -> f64 {
    for _ in 0..iters / 10 + 1 {
        f(); // warm-up
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let ns = start.elapsed().as_nanos() as f64 / f64::from(iters);
    println!("BENCH {name:<44} {ns:>12.1} ns/op  ({iters} iterations)");
    ns
}

fn sample_run(n: usize) -> RunReport {
    let mut targets = Vec::new();
    for i in 0..n {
        let mut t = healthy_target(&format!("t{i}.test"));
        t.dns.https = Some(dns::Svcb {
            priority: 1,
            alpn: vec!["h3".into(), "h2".into()],
            ech: true,
            ..dns::Svcb::default()
        });
        t.quic = probe::QuicResult {
            status: Status::Ok,
            rtt_us: 20_000,
            versions: vec![quic::VERSION_1],
        };
        targets.push(t);
    }
    run_of(targets, vec![resolver(true, false), resolver(true, true)])
}

#[cfg(target_os = "linux")]
fn rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmRSS:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

#[test]
#[ignore]
fn bench_core_paths() {
    let mut hostbuf = b"WWW.Example-SubDomain.Host-Name.Example.COM".to_vec();
    hostbuf.resize(253, b'X');
    bench(
        "ascii::lowercase_in_place (253 B, Assembly)",
        500_000,
        || {
            let mut b = std::hint::black_box(hostbuf.clone());
            crate::ascii::lowercase_in_place(std::hint::black_box(&mut b));
            std::hint::black_box(b);
        },
    );
    bench("[..].make_ascii_lowercase (253 B, std)", 500_000, || {
        let mut b = std::hint::black_box(hostbuf.clone());
        b.make_ascii_lowercase();
        std::hint::black_box(b);
    });
    let q = dns::build_query(5, "svc.test", dns::TYPE_HTTPS, true).unwrap();
    let resp = make_response(
        &q,
        0x8180,
        &[
            (dns::TYPE_HTTPS, https_rdata()),
            (dns::TYPE_A, vec![1, 1, 1, 1]),
        ],
    );
    bench("dns::build_query", 200_000, || {
        std::hint::black_box(
            dns::build_query(
                7,
                std::hint::black_box("www.example.com"),
                dns::TYPE_A,
                true,
            )
            .unwrap(),
        );
    });
    bench("dns::parse_response (HTTPS + A)", 200_000, || {
        std::hint::black_box(
            dns::parse_response(std::hint::black_box(&resp), 5, "svc.test", dns::TYPE_HTTPS)
                .unwrap(),
        );
    });
    let d = [1u8; 8];
    let s = [2u8; 8];
    let vn = vn_packet(&s, &d, &[quic::VERSION_1, quic::VERSION_2]);
    bench("quic::build_probe (1200 B)", 200_000, || {
        std::hint::black_box(quic::build_probe(&d, &s, 1200));
    });
    bench("quic::parse_version_negotiation", 500_000, || {
        std::hint::black_box(
            quic::parse_version_negotiation(std::hint::black_box(&vn), &d, &s).unwrap(),
        );
    });
    let run = sample_run(8);
    let env = env_with(|_| {});
    bench("intel::classify (8 targets)", 50_000, || {
        std::hint::black_box(intel::classify(Some(&env), std::hint::black_box(&run)));
    });
    bench("engine::score (8 targets)", 200_000, || {
        std::hint::black_box(engine::score(std::hint::black_box(&run)));
    });
    let diags = intel::classify(Some(&env), &run);
    let mut decider = Decider::new(0, 10);
    let mut t = 0u64;
    bench("decide::Decider::step", 500_000, || {
        t += 1;
        std::hint::black_box(decider.step(t, Some(800), &diags));
    });
    let rec = engine::encode_run(&run, 1);
    bench("wire::encode (run report, 8 targets)", 50_000, || {
        std::hint::black_box(wire::encode(std::hint::black_box(&rec)).unwrap());
    });
    let bytes = wire::encode(&rec).unwrap();
    println!("INFO  run report size (8 targets): {} bytes", bytes.len());
    bench("wire::decode (run report, 8 targets)", 50_000, || {
        std::hint::black_box(wire::decode(std::hint::black_box(&bytes)).unwrap());
    });
    let _g = registry_guard();
    bench("api::create + api::destroy", 100_000, || {
        let h = api::create(None);
        api::destroy(h);
    });
}

#[test]
#[ignore]
fn bench_loopback_diagnose() {
    let _g = registry_guard();
    let srv = fake_dns(DnsMode::Normal);
    let (port, _sink) = tcp_sink();
    let req = request(
        &(0..4)
            .map(|i| format!("t{i}.test:{port}"))
            .collect::<Vec<_>>(),
    );
    for quic_on in [0, 1] {
        let h = api::create(Some(&config_bytes(|r| {
            r.int(tags::config::DNS_SAMPLES, 3)
                .int(tags::config::TCP_SAMPLES, 3)
                .int(tags::config::QUIC, quic_on);
        })));
        api::set_environment(h, &env_bytes(&srv.addr.to_string()));
        let name = format!("diagnose + evaluate (4 targets, loopback, quic={quic_on})");
        let ns = bench(&name, 30, || {
            assert_eq!(
                wire::decode(&api::diagnose(h, &req)).unwrap().status(),
                Some(0)
            );
            std::hint::black_box(api::evaluate(h));
        });
        println!("INFO  {name}: {:.2} ms per run", ns / 1e6);
        api::destroy(h);
    }
}

#[test]
#[ignore]
fn stress_long_running_session() {
    let _g = registry_guard();
    let srv = fake_dns(DnsMode::Normal);
    let (port, _sink) = tcp_sink();
    let h = api::create(Some(&config_bytes(|r| {
        r.int(tags::config::DNS_SAMPLES, 1)
            .int(tags::config::TCP_SAMPLES, 1)
            .int(tags::config::QUIC, 0);
    })));
    let env = env_bytes(&srv.addr.to_string());
    let req = request(&[format!("svc.test:{port}"), format!("127.0.0.1:{port}")]);
    let warm = 200;
    let cycles = 5000;
    #[cfg(target_os = "linux")]
    let mut baseline = 0;
    let start = Instant::now();
    for i in 0..cycles {
        if i % 50 == 0 {
            api::network_changed(h);
        }
        assert_eq!(api::set_environment(h, &env), code::OK);
        assert_eq!(
            wire::decode(&api::diagnose(h, &req)).unwrap().status(),
            Some(0)
        );
        assert_eq!(wire::decode(&api::evaluate(h)).unwrap().status(), Some(0));
        if i % 7 == 0 {
            let _ = api::mark_applied(h, i % 13);
        }
        #[cfg(target_os = "linux")]
        if i == warm {
            baseline = rss_kib();
        }
    }
    let elapsed = start.elapsed();
    api::destroy(h);
    println!(
        "STRESS {cycles} diagnose/evaluate cycles in {:.1} s",
        elapsed.as_secs_f64()
    );
    #[cfg(target_os = "linux")]
    {
        let end = rss_kib();
        println!(
            "STRESS RSS after warm-up {baseline} KiB, at end {end} KiB (Δ {} KiB)",
            end as i64 - baseline as i64
        );
        assert!(
            end < baseline + 4096,
            "resident memory grew by more than 4 MiB: {baseline} → {end}"
        );
    }
    let _ = warm;
}

#[test]
#[ignore]
fn stress_init_shutdown_and_concurrency() {
    let _g = registry_guard();
    let start = Instant::now();
    let threads: Vec<_> = (0..8)
        .map(|_| {
            thread::spawn(|| {
                for _ in 0..20_000 {
                    let h = api::create(None);
                    if h > 0 {
                        let _ = api::evaluate(h);
                        let _ = api::network_changed(h);
                        assert_eq!(api::destroy(h), code::OK);
                    }
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(api::engine_count(), 0);
    println!(
        "STRESS 160000 create/use/destroy cycles across 8 threads in {:.2} s",
        start.elapsed().as_secs_f64()
    );
}
