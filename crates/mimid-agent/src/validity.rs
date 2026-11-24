//! The validity period of an X.509 certificate, read from its DER
//! (RFC 5280 §4.1.2.5; docs/design/frontend-auth.md §5.4; bead
//! mimid-e13m.19).
//!
//! The agent serves a certificate from whichever source `[tls]` names, and
//! §5.4 asks it to warn before that certificate expires, to keep serving
//! an expired one with an hourly ERROR rather than close the listener, and
//! to renew at two thirds of **the lifetime**. All three need the leaf's
//! own `notBefore` and `notAfter`, which nothing else in the tree reads:
//! rcgen writes certificates, and rustls-webpki checks a validity against
//! a time without telling the caller what the validity is.
//!
//! So this module walks just far enough into the DER to find the
//! `validity` field and stops:
//!
//! ```text
//! Certificate     ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
//! TBSCertificate  ::= SEQUENCE { version [0] EXPLICIT DEFAULT v1,
//!                                serialNumber  INTEGER,
//!                                signature     AlgorithmIdentifier,
//!                                issuer        Name,
//!                                validity      Validity,
//!                                ... }
//! Validity        ::= SEQUENCE { notBefore Time, notAfter Time }
//! Time            ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }
//! ```
//!
//! Decoding is strict, as AGENTS.md asks of every wire format mimid
//! parses: definite lengths in their shortest form only, no indefinite
//! length, no high-tag-number form, no trailing bytes inside any value
//! this module reads, and a size cap ([`MAX_CERTIFICATE`]) and a length
//! cap ([`MAX_LENGTH_OCTETS`]) enforced while parsing. RFC 5280's own
//! narrowing of the two time types is enforced too: a `UTCTime` is
//! exactly `YYMMDDHHMMSSZ` with the year read per §4.1.2.5.1, a
//! `GeneralizedTime` exactly `YYYYMMDDHHMMSSZ` per §4.1.2.5.2, with
//! seconds present, `Z` as the only zone and no fractional part.
//!
//! A certificate this module refuses is not rejected by the agent: the
//! certificate still serves connections, and the caller treats the
//! validity as unknown and says so in the log. The agent is not a relying
//! party here; it is reading its own certificate to decide when to
//! complain.
//!
//! # Limitations
//!
//! - It reads the leaf and nothing else. A chain whose intermediate
//!   expires first is not noticed.
//! - It does not verify the certificate, its signature or its names, and
//!   must never be used to: the only question it answers is what two time
//!   fields say.
//! - `UTCTime` cannot name a year past 2049, so a certificate with a
//!   longer life must use `GeneralizedTime`, which RFC 5280 §4.1.2.5
//!   already requires.
//! - A leap second (`:60`) is refused rather than rounded, so a
//!   certificate carrying one reads as unknown.

use std::time::SystemTime;

/// The largest certificate DER this module will look at. A leaf with a
/// long name list and an SCT extension is a few kilobytes; this is far
/// above any of them and keeps a malformed length from making the parser
/// walk a huge buffer. INVENTED, NOT FROM SPEC.
pub const MAX_CERTIFICATE: usize = 64 * 1024;

/// The most length octets a long-form DER length may use here, which is
/// what [`MAX_CERTIFICATE`] needs. INVENTED, NOT FROM SPEC.
pub const MAX_LENGTH_OCTETS: usize = 3;

/// How deep this module ever descends: Certificate, TBSCertificate,
/// Validity. Named so the walk's shape is checkable. INVENTED, NOT FROM
/// SPEC.
pub const MAX_DEPTH: usize = 3;

/// DER tags this module knows.
mod tag {
    /// `INTEGER`.
    pub const INTEGER: u8 = 0x02;
    /// `UTCTime`.
    pub const UTC_TIME: u8 = 0x17;
    /// `GeneralizedTime`.
    pub const GENERALIZED_TIME: u8 = 0x18;
    /// `SEQUENCE` (constructed).
    pub const SEQUENCE: u8 = 0x30;
    /// `[0]` constructed, the explicit `version` of TBSCertificate.
    pub const VERSION: u8 = 0xa0;
}

/// Why a certificate's validity could not be read. The certificate is
/// still served; only the agent's own expiry check is given up on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ValidityError {
    /// The DER is not shaped the way RFC 5280 says, or uses an encoding
    /// this module refuses. `at` names the step that stopped.
    #[error("the certificate's DER could not be read: {at}")]
    Der {
        /// What the parser was doing.
        at: &'static str,
    },
    /// A `notBefore` or `notAfter` is not a time RFC 5280 §4.1.2.5
    /// allows.
    #[error("the certificate's {field} is not an RFC 5280 time: {detail}")]
    Time {
        /// `notBefore` or `notAfter`.
        field: &'static str,
        /// What was wrong with it.
        detail: &'static str,
    },
}

/// A certificate's validity period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity {
    /// RFC 5280 `notBefore`.
    pub not_before: SystemTime,
    /// RFC 5280 `notAfter`.
    pub not_after: SystemTime,
}

impl Validity {
    /// How long the certificate is valid for in all, or `None` if
    /// `notAfter` is before `notBefore`.
    #[must_use]
    pub fn lifetime(&self) -> Option<std::time::Duration> {
        self.not_after.duration_since(self.not_before).ok()
    }
}

/// Reads `der`'s validity period: an end-entity certificate as rustls
/// holds it, DER, not PEM.
///
/// # Errors
///
/// [`ValidityError`] for a certificate this module will not read. The
/// caller treats that as an unknown validity, never as a bad
/// certificate: this is not a verifier.
pub fn validity(der: &[u8]) -> Result<Validity, ValidityError> {
    if der.is_empty() || der.len() > MAX_CERTIFICATE {
        return Err(ValidityError::Der {
            at: "the certificate's size",
        });
    }
    // Certificate ::= SEQUENCE { tbsCertificate, ... }. Only the first
    // field is wanted, so the rest of the SEQUENCE is left unread; the
    // bytes after the SEQUENCE itself are not, since a certificate is
    // one DER value and nothing more.
    let (certificate, after) = tlv(der, tag::SEQUENCE, "the outer Certificate SEQUENCE")?;
    if !after.is_empty() {
        return Err(ValidityError::Der {
            at: "trailing bytes after the Certificate",
        });
    }
    let (tbs, _) = tlv(certificate, tag::SEQUENCE, "the TBSCertificate SEQUENCE")?;
    // version [0] EXPLICIT, absent in a v1 certificate.
    let tbs = match peek(tbs) {
        Some(tag::VERSION) => skip(tbs, tag::VERSION, "the version")?,
        _ => tbs,
    };
    let tbs = skip(tbs, tag::INTEGER, "the serialNumber")?;
    let tbs = skip(tbs, tag::SEQUENCE, "the signature AlgorithmIdentifier")?;
    let tbs = skip(tbs, tag::SEQUENCE, "the issuer Name")?;
    let (period, _) = tlv(tbs, tag::SEQUENCE, "the validity SEQUENCE")?;
    let (not_before, rest) = time(period, "notBefore")?;
    let (not_after, rest) = time(rest, "notAfter")?;
    if !rest.is_empty() {
        return Err(ValidityError::Der {
            at: "trailing bytes in the validity SEQUENCE",
        });
    }
    Ok(Validity {
        not_before,
        not_after,
    })
}

/// The tag of the value `input` starts with, if it starts with one.
fn peek(input: &[u8]) -> Option<u8> {
    input.first().copied()
}

/// The contents of the value `input` starts with, which must carry tag
/// `want`, and what follows it. `at` names the step, for the error.
fn tlv<'a>(
    input: &'a [u8],
    want: u8,
    at: &'static str,
) -> Result<(&'a [u8], &'a [u8]), ValidityError> {
    let der = |at| ValidityError::Der { at };
    let (&tag, rest) = input.split_first().ok_or_else(|| der(at))?;
    if tag != want {
        return Err(der(at));
    }
    let (&first, rest) = rest.split_first().ok_or_else(|| der(at))?;
    let (length, rest) = if first < 0x80 {
        // Short form: the length is the octet itself.
        (usize::from(first), rest)
    } else if first == 0x80 {
        // Indefinite length: BER, not DER.
        return Err(der("an indefinite length, which DER forbids"));
    } else if first == 0xff {
        return Err(der("a reserved length octet"));
    } else {
        let count = usize::from(first & 0x7f);
        if count > MAX_LENGTH_OCTETS {
            return Err(der("a length too large for a certificate"));
        }
        let (octets, rest) = rest.split_at_checked(count).ok_or_else(|| der(at))?;
        // DER: the shortest form only, so the first octet is non-zero and
        // the value does not fit in the short form.
        if octets.first() == Some(&0) {
            return Err(der("a length with a leading zero octet"));
        }
        let length = octets
            .iter()
            .fold(0usize, |acc, &byte| (acc << 8) | usize::from(byte));
        if length < 0x80 {
            return Err(der("a long-form length that fits the short form"));
        }
        (length, rest)
    };
    let (value, after) = rest.split_at_checked(length).ok_or_else(|| der(at))?;
    Ok((value, after))
}

/// What follows the value `input` starts with, which must carry tag
/// `want`.
fn skip<'a>(input: &'a [u8], want: u8, at: &'static str) -> Result<&'a [u8], ValidityError> {
    tlv(input, want, at).map(|(_, after)| after)
}

/// The `Time` that `input` starts with, and what follows it. `field` is
/// `notBefore` or `notAfter`, for the error.
fn time<'a>(input: &'a [u8], field: &'static str) -> Result<(SystemTime, &'a [u8]), ValidityError> {
    let bad = |detail| ValidityError::Time { field, detail };
    // RFC 5280 §4.1.2.5: a CHOICE of the two, and nothing else.
    let (digits, after, year) = match peek(input) {
        Some(tag::UTC_TIME) => {
            let (value, after) = tlv(input, tag::UTC_TIME, "a UTCTime")?;
            // §4.1.2.5.1: YYMMDDHHMMSSZ, and the two-digit year is
            // 1950..=2049 — 50 and up is 19xx.
            let value =
                exactly::<13>(value).ok_or_else(|| bad("a UTCTime that is not 13 bytes"))?;
            let yy = i32::from(pair(&value[0..2]).ok_or_else(|| bad("a non-digit year"))?);
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
            (value[2..].to_vec(), after, year)
        }
        Some(tag::GENERALIZED_TIME) => {
            let (value, after) = tlv(input, tag::GENERALIZED_TIME, "a GeneralizedTime")?;
            // §4.1.2.5.2: YYYYMMDDHHMMSSZ, seconds present, no
            // fractional seconds.
            let value = exactly::<15>(value)
                .ok_or_else(|| bad("a GeneralizedTime that is not 15 bytes"))?;
            let century = i32::from(pair(&value[0..2]).ok_or_else(|| bad("a non-digit year"))?);
            let yy = i32::from(pair(&value[2..4]).ok_or_else(|| bad("a non-digit year"))?);
            (value[4..].to_vec(), after, century * 100 + yy)
        }
        _ => {
            return Err(bad(
                "neither a UTCTime nor a GeneralizedTime, the only two RFC 5280 allows",
            ));
        }
    };
    // What is left of both forms is MMDDHHMMSS then the zone.
    let &[zone] = &digits[10..] else {
        return Err(bad("a time with no zone"));
    };
    if zone != b'Z' {
        return Err(bad("a zone other than Z, which RFC 5280 requires"));
    }
    let field_at = |i: usize| pair(&digits[i..i + 2]).ok_or_else(|| bad("a non-digit field"));
    let month = time::Month::try_from(field_at(0)?).map_err(|_| bad("a month outside 1 to 12"))?;
    let date = time::Date::from_calendar_date(year, month, field_at(2)?)
        .map_err(|_| bad("a day that month does not have"))?;
    let clock = time::Time::from_hms(field_at(4)?, field_at(6)?, field_at(8)?)
        .map_err(|_| bad("an hour, minute or second out of range"))?;
    let at = time::PrimitiveDateTime::new(date, clock).assume_utc();
    Ok((SystemTime::from(at), after))
}

/// `value` as an array of exactly `N` bytes, or `None`.
fn exactly<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
    value.try_into().ok()
}

/// Two ASCII digits as a number.
fn pair(digits: &[u8]) -> Option<u8> {
    match digits {
        [tens, ones] if tens.is_ascii_digit() && ones.is_ascii_digit() => {
            Some((tens - b'0') * 10 + (ones - b'0'))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DER value: tag, length in its shortest form, contents. An
    /// encoder of its own, so the fixtures below do not come from the
    /// parser under test.
    fn tlv_bytes(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = contents.len();
        if n < 0x80 {
            v.push(u8::try_from(n).unwrap());
        } else if n <= 0xff {
            v.extend_from_slice(&[0x81, u8::try_from(n).unwrap()]);
        } else {
            v.extend_from_slice(&[
                0x82,
                u8::try_from(n >> 8).unwrap(),
                u8::try_from(n & 0xff).unwrap(),
            ]);
        }
        v.extend_from_slice(contents);
        v
    }

    /// A certificate's outer shape, enough to reach the validity, built
    /// from RFC 5280 §4.1's ASN.1 with a comment per field. `period` is
    /// the two encoded `Time` values; `version` says whether the
    /// optional `[0] EXPLICIT` version is there.
    fn certificate_with(period: &[u8], version: bool) -> Vec<u8> {
        let mut tbs = Vec::new();
        if version {
            // version [0] EXPLICIT { INTEGER 2 }, i.e. v3.
            tbs.extend_from_slice(&tlv_bytes(tag::VERSION, &tlv_bytes(tag::INTEGER, &[0x02])));
        }
        // serialNumber INTEGER 1.
        tbs.extend_from_slice(&tlv_bytes(tag::INTEGER, &[0x01]));
        // signature AlgorithmIdentifier: an empty SEQUENCE is enough,
        // since nothing here reads it.
        tbs.extend_from_slice(&tlv_bytes(tag::SEQUENCE, &[]));
        // issuer Name: likewise.
        tbs.extend_from_slice(&tlv_bytes(tag::SEQUENCE, &[]));
        tbs.extend_from_slice(&tlv_bytes(tag::SEQUENCE, period));
        // subject and the rest of TBSCertificate, unread: one empty
        // SEQUENCE stands for all of it.
        tbs.extend_from_slice(&tlv_bytes(tag::SEQUENCE, &[]));
        let mut body = tlv_bytes(tag::SEQUENCE, &tbs);
        // signatureAlgorithm and signatureValue, also unread.
        body.extend_from_slice(&tlv_bytes(tag::SEQUENCE, &[]));
        body.extend_from_slice(&tlv_bytes(0x03, &[0x00]));
        tlv_bytes(tag::SEQUENCE, &body)
    }

    fn certificate(period: &[u8]) -> Vec<u8> {
        certificate_with(period, true)
    }

    /// `YYMMDDHHMMSSZ` as a UTCTime value.
    fn utc(text: &str) -> Vec<u8> {
        tlv_bytes(tag::UTC_TIME, text.as_bytes())
    }

    /// `YYYYMMDDHHMMSSZ` as a GeneralizedTime value.
    fn generalized(text: &str) -> Vec<u8> {
        tlv_bytes(tag::GENERALIZED_TIME, text.as_bytes())
    }

    /// Seconds since the Unix epoch of a `SystemTime`.
    fn unix(at: SystemTime) -> i64 {
        match at.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(since) => i64::try_from(since.as_secs()).unwrap(),
            Err(before) => -i64::try_from(before.duration().as_secs()).unwrap(),
        }
    }

    #[test]
    fn a_utctime_pair_is_read_with_the_rfc_5280_year_window() {
        let mut period = utc("260101000000Z");
        period.extend_from_slice(&utc("491231235959Z"));
        let got = validity(&certificate(&period)).unwrap();
        // 2026-01-01T00:00:00Z and 2049-12-31T23:59:59Z, the last
        // instant a UTCTime can name (§4.1.2.5.1).
        assert_eq!(unix(got.not_before), 1_767_225_600);
        assert_eq!(unix(got.not_after), 2_524_607_999);
    }

    /// §4.1.2.5.1: 50 and up is 19xx, so the window is 1950 to 2049.
    #[test]
    fn a_utctime_year_of_fifty_or_more_is_in_the_nineteen_hundreds() {
        let mut period = utc("500101000000Z");
        period.extend_from_slice(&utc("510101000000Z"));
        let got = validity(&certificate(&period)).unwrap();
        // 1950-01-01T00:00:00Z, before the epoch.
        assert_eq!(unix(got.not_before), -631_152_000);
    }

    #[test]
    fn a_generalizedtime_pair_is_read() {
        let mut period = generalized("20261124000000Z");
        period.extend_from_slice(&generalized("20991124000000Z"));
        let got = validity(&certificate(&period)).unwrap();
        assert_eq!(unix(got.not_before), 1_795_478_400);
        assert_eq!(unix(got.not_after), 4_099_161_600);
        assert_eq!(
            got.lifetime().unwrap().as_secs(),
            u64::try_from(4_099_161_600i64 - 1_795_478_400).unwrap()
        );
    }

    /// The two forms mix, as a certificate issued across 2050 must.
    #[test]
    fn the_two_time_forms_mix_in_one_certificate() {
        let mut period = utc("491231000000Z");
        period.extend_from_slice(&generalized("20500101000000Z"));
        let got = validity(&certificate(&period)).unwrap();
        assert_eq!(got.lifetime().unwrap().as_secs(), 24 * 60 * 60);
    }

    #[test]
    fn a_notafter_before_the_notbefore_has_no_lifetime() {
        let mut period = generalized("20261124000000Z");
        period.extend_from_slice(&generalized("20251124000000Z"));
        let got = validity(&certificate(&period)).unwrap();
        assert!(got.lifetime().is_none());
    }

    /// A certificate with no `version` field is v1 and still readable.
    #[test]
    fn a_v1_certificate_without_the_explicit_version_is_read() {
        let mut period = utc("260101000000Z");
        period.extend_from_slice(&utc("270101000000Z"));
        let got = validity(&certificate_with(&period, false)).unwrap();
        assert_eq!(unix(got.not_before), 1_767_225_600);
        assert_eq!(unix(got.not_after), 1_798_761_600);
    }

    /// A fixture from an independent implementation, which AGENTS.md
    /// ranks above anything this file encodes: rcgen issues a real
    /// certificate with a chosen `notBefore` and `notAfter`, and the
    /// parser has to read back exactly those. This is also the shape the
    /// agent actually parses, since `local-ca` leaves come from rcgen and
    /// an ACME certificate has the same fields in the same order.
    #[test]
    fn an_rcgen_certificate_reads_back_the_dates_it_was_given() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["mimid.example".to_owned()]).unwrap();
        // 2026-03-04T05:06:07Z to 2031-03-04T05:06:07Z: past 2049 is
        // what forces GeneralizedTime, and this is well inside it, so
        // rcgen writes UTCTime and the two-digit year path is exercised
        // against another implementation's bytes.
        let from = time::OffsetDateTime::from_unix_timestamp(1_772_593_567).unwrap();
        let to = from + time::Duration::days(5 * 365);
        params.not_before = from;
        params.not_after = to;
        let der = params.self_signed(&key).unwrap();
        let got = validity(der.der()).unwrap();
        assert_eq!(unix(got.not_before), 1_772_593_567);
        assert_eq!(unix(got.not_after), unix(got.not_before) + 5 * 365 * 86_400);
        assert_eq!(got.lifetime().unwrap().as_secs(), 5 * 365 * 86_400);
    }

    /// The same, for a certificate whose `notAfter` is past 2049, where
    /// RFC 5280 §4.1.2.5 makes the encoder switch to GeneralizedTime.
    #[test]
    fn an_rcgen_certificate_past_2049_uses_generalizedtime() {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["mimid.example".to_owned()]).unwrap();
        let from = time::OffsetDateTime::from_unix_timestamp(1_772_593_567).unwrap();
        // 2050-01-01T00:00:00Z.
        let to = time::OffsetDateTime::from_unix_timestamp(2_524_608_000).unwrap();
        params.not_before = from;
        params.not_after = to;
        let der = params.self_signed(&key).unwrap();
        let got = validity(der.der()).unwrap();
        assert_eq!(unix(got.not_after), 2_524_608_000);
    }

    #[test]
    fn hostile_input_is_refused() {
        let mut period = utc("260101000000Z");
        period.extend_from_slice(&utc("270101000000Z"));
        let good = certificate(&period);

        assert!(matches!(
            validity(&[]),
            Err(ValidityError::Der {
                at: "the certificate's size"
            })
        ));
        assert!(matches!(
            validity(&vec![0u8; MAX_CERTIFICATE + 1]),
            Err(ValidityError::Der {
                at: "the certificate's size"
            })
        ));
        // Truncated at every length: never a panic, never a success.
        for cut in 0..good.len() {
            assert!(validity(&good[..cut]).is_err(), "truncated to {cut}");
        }
        // A byte after the Certificate.
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert!(matches!(
            validity(&trailing),
            Err(ValidityError::Der {
                at: "trailing bytes after the Certificate"
            })
        ));
        // Not a SEQUENCE at all.
        assert!(validity(&[0x02, 0x01, 0x00]).is_err());
        // An indefinite length, which is BER and not DER.
        assert!(matches!(
            validity(&[0x30, 0x80, 0x00, 0x00]),
            Err(ValidityError::Der {
                at: "an indefinite length, which DER forbids"
            })
        ));
        // A long-form length that the short form could have held.
        assert!(matches!(
            validity(&[0x30, 0x81, 0x02, 0x30, 0x00]),
            Err(ValidityError::Der {
                at: "a long-form length that fits the short form"
            })
        ));
        // A length with a leading zero octet.
        assert!(matches!(
            validity(&[0x30, 0x82, 0x00, 0x81, 0x30, 0x00]),
            Err(ValidityError::Der {
                at: "a length with a leading zero octet"
            })
        ));
        // More length octets than a certificate can need.
        assert!(matches!(
            validity(&[0x30, 0x84, 0x01, 0x00, 0x00, 0x00]),
            Err(ValidityError::Der {
                at: "a length too large for a certificate"
            })
        ));
        // The reserved length octet.
        assert!(matches!(
            validity(&[0x30, 0xff, 0x00]),
            Err(ValidityError::Der {
                at: "a reserved length octet"
            })
        ));
    }

    #[test]
    fn a_time_rfc_5280_forbids_is_refused() {
        let good = utc("260101000000Z");
        // Each of these pairs with a valid notBefore, so the error is
        // about the time under test.
        let cases: [(Vec<u8>, &str); 9] = [
            // No zone at all: 12 bytes instead of 13.
            (utc("26010100000"), "a UTCTime that is not 13 bytes"),
            // A zone other than Z.
            (
                utc("260101000000+"),
                "a zone other than Z, which RFC 5280 requires",
            ),
            // An offset zone, which is longer than 13 bytes.
            (utc("260101000000+0100"), "a UTCTime that is not 13 bytes"),
            // Fractional seconds, which §4.1.2.5.2 forbids.
            (
                generalized("20260101000000.5Z"),
                "a GeneralizedTime that is not 15 bytes",
            ),
            // Seconds left out, which §4.1.2.5 requires.
            (
                generalized("202601010000Z"),
                "a GeneralizedTime that is not 15 bytes",
            ),
            // Non-digits where digits belong.
            (utc("2x0101000000Z"), "a non-digit year"),
            (utc("26xx01000000Z"), "a non-digit field"),
            // Out of range.
            (utc("261301000000Z"), "a month outside 1 to 12"),
            (utc("260230000000Z"), "a day that month does not have"),
        ];
        for (bad, detail) in cases {
            let mut period = good.clone();
            period.extend_from_slice(&bad);
            match validity(&certificate(&period)) {
                Err(ValidityError::Time { field, detail: got }) => {
                    assert_eq!(field, "notAfter");
                    assert_eq!(got, detail, "for {bad:02x?}");
                }
                other => panic!("{bad:02x?}: {other:?}"),
            }
        }
    }

    /// A leap second is refused rather than rounded, as the module's
    /// limitations say.
    #[test]
    fn a_leap_second_is_refused() {
        let mut period = utc("260101000000Z");
        period.extend_from_slice(&utc("261231235960Z"));
        assert!(matches!(
            validity(&certificate(&period)),
            Err(ValidityError::Time {
                detail: "an hour, minute or second out of range",
                ..
            })
        ));
    }

    /// A time type RFC 5280 does not allow, here `IA5String`.
    #[test]
    fn a_time_of_another_asn1_type_is_refused() {
        let mut period = utc("260101000000Z");
        period.extend_from_slice(&[0x16, 0x0d]);
        period.extend_from_slice(b"260101000000Z");
        assert!(matches!(
            validity(&certificate(&period)),
            Err(ValidityError::Time {
                field: "notAfter",
                detail: "neither a UTCTime nor a GeneralizedTime, the only two RFC 5280 allows",
            })
        ));
    }

    #[test]
    fn a_third_time_in_the_validity_sequence_is_refused() {
        let mut period = utc("260101000000Z");
        period.extend_from_slice(&utc("270101000000Z"));
        period.extend_from_slice(&utc("280101000000Z"));
        assert!(matches!(
            validity(&certificate(&period)),
            Err(ValidityError::Der {
                at: "trailing bytes in the validity SEQUENCE"
            })
        ));
    }
}
