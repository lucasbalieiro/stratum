#![no_main]

mod common;

use codec_sv2::SerializedFrame;
use framing_sv2::header::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u8>| {
    // Direct frame path: anything that parses as a frame and whose payload
    // parses as an Sv2 message must survive the canonical re-encode oracle.
    if let Ok(mut frame) = SerializedFrame::from_bytes(data.clone().into()) {
        let header = frame.header();
        let payload_len = frame.payload().len();
        let mut payload = vec![0u8; payload_len];
        payload.copy_from_slice(frame.payload());

        // negotiated_extensions is unknown for raw input; use an empty list.
        let _ = common::check_parsed_message(header, &mut payload, None, &[]);
    }

    // Also exercise the header-only parse path so a frame with a bad length
    // still drives the SizeHint logic (already covered by fuzz_sv2_frame_header,
    // but kept here for a single entry point).
    let _ = Header::from_bytes(&data);
});