#![no_main]

use codec_sv2::SerializedFrame;
use framing_sv2::framing::EncodableFrame;
use framing_sv2::framing::SizeHint;
use framing_sv2::header::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u8>| {
    // Header roundtrip: from_bytes -> write_into -> from_bytes.
    if data.len() >= 6 {
        if let Ok(header) = Header::from_bytes(&data) {
            let mut buf = [0u8; 6];
            header
                .write_into(&mut buf)
                .expect("write_into must succeed for a 6-byte destination");
            let reparsed = Header::from_bytes(&buf).expect("written header must parse");
            assert_eq!(reparsed.ext_type(), header.ext_type());
            assert_eq!(reparsed.msg_type(), header.msg_type());
            assert_eq!(reparsed.payload_length(), header.payload_length());
            assert_eq!(reparsed.channel_msg(), header.channel_msg());
        }
    }

    // parse_header SizeHint accuracy.
    match framing_sv2::framing::SerializedFrame::<Vec<u8>>::parse_header(&data) {
        Ok(header) => {
            assert_eq!(data.len(), 6 + header.payload_length());
        }
        Err(SizeHint::Missing(n)) => {
            if data.len() < 6 {
                assert_eq!(n, 6 - data.len());
            } else {
                let header = Header::from_bytes(&data).expect("header must parse");
                let expected = 6 + header.payload_length();
                assert_eq!(n, expected - data.len());
            }
        }
        Err(SizeHint::Surplus(n)) => {
            let header = Header::from_bytes(&data).expect("header must parse");
            let expected = 6 + header.payload_length();
            assert_eq!(n, data.len() - expected);
        }
    }

    // Pool-backed frame invariants.
    if let Ok(frame) = SerializedFrame::from_bytes(data.clone().into()) {
        // encode_into rejects a destination of the wrong length.
        if data.len() > 0 {
            let mut short = vec![0u8; data.len() - 1];
            assert!(frame.clone().encode_into(&mut short).is_err());
            let mut long = vec![0u8; data.len() + 1];
            assert!(frame.clone().encode_into(&mut long).is_err());
        }

        // encode_into copies the frame verbatim.
        let mut out = vec![0u8; data.len()];
        frame
            .clone()
            .encode_into(&mut out)
            .expect("encode_into must succeed");
        assert_eq!(out, data);

        // channel_id() reflects the first payload word when the channel bit is set.
        let cid = frame.channel_id();
        if frame.header().channel_msg() && data.len() >= 6 + 4 {
            assert!(cid.is_some());
            let expected =
                u32::from_le_bytes(data[6..10].try_into().expect("four payload bytes"));
            assert_eq!(cid.unwrap(), expected);
        } else {
            assert!(cid.is_none());
        }

        // into_owned preserves the bytes.
        let owned = frame.into_owned();
        assert_eq!(owned.as_bytes(), data.as_slice());
    }
});