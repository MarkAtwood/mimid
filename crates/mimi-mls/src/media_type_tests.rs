//! Oracle: the §6.2.2 struct, encoded by hand (one-byte varint lengths).

use super::*;

/// A media type and its (name, value) parameters.
type Item<'a> = (&'a [u8], &'a [(&'a [u8], &'a [u8])]);

/// A MediaTypeList holding the given items.
fn list(items: &[Item<'_>]) -> Vec<u8> {
    let v = |b: &[u8]| [vec![u8::try_from(b.len()).unwrap()], b.to_vec()].concat();
    let body: Vec<u8> = items
        .iter()
        .flat_map(|(t, params)| {
            let params: Vec<u8> = params
                .iter()
                .flat_map(|(n, val)| [v(n), v(val)].concat())
                .collect();
            [v(t), v(&params)].concat()
        })
        .collect();
    v(&body)
}

#[test]
fn the_drafts_examples_decode() {
    let ok = list(&[
        (b"image/png", &[]),
        (b"text/plain", &[(b"charset", b"UTF-8")]),
        (b"application/json", &[]),
    ]);
    assert_eq!(check_media_type_list(&ok), Ok(()));
    // A value may hold a space and a tab, which a quoted-string would carry.
    let spaced = list(&[(b"text/plain", &[(b"x", b"a b\tc")])]);
    assert_eq!(check_media_type_list(&spaced), Ok(()));
}

#[test]
fn malformed_lists_are_refused() {
    assert_eq!(
        check_media_type_list(&list(&[])),
        Err(MediaTypeError::Empty)
    );
    assert_eq!(
        check_media_type_list(&[0x05, 0x01]),
        Err(MediaTypeError::Encoding)
    );
    let mut trailing = list(&[(b"image/png", &[])]);
    trailing.push(0x00);
    assert_eq!(
        check_media_type_list(&trailing),
        Err(MediaTypeError::Encoding)
    );
    for bad in [
        &b"image"[..],
        b"/png",
        b"image/",
        b"im age/png",
        b"image/png/x",
    ] {
        assert_eq!(
            check_media_type_list(&list(&[(bad, &[])])),
            Err(MediaTypeError::Type),
            "{:?}",
            String::from_utf8_lossy(bad)
        );
    }
    assert_eq!(
        check_media_type_list(&list(&[(b"text/plain", &[(b"char set", b"x")])])),
        Err(MediaTypeError::ParameterName)
    );
    assert_eq!(
        check_media_type_list(&list(&[(b"text/plain", &[(b"", b"x")])])),
        Err(MediaTypeError::ParameterName)
    );
    assert_eq!(
        check_media_type_list(&list(&[(b"text/plain", &[(b"x", b"\x7f")])])),
        Err(MediaTypeError::ParameterValue)
    );
    assert_eq!(
        check_media_type_list(&list(&[(b"text/plain", &[(b"x", "é".as_bytes())])])),
        Err(MediaTypeError::ParameterValue)
    );
}
