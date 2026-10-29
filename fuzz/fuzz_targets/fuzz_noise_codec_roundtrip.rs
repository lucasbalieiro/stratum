#![no_main]

use libfuzzer_sys::fuzz_target;

use codec_sv2::{
    self, Decoded, Decrypted, ExpectsHandshakeMessage, Handshake, InitiatorSent, NoiseDecoder,
    NoiseEncoder, SerializedFrame as CodecSerializedFrame, TransportDecryptState,
    TransportEncryptState, ENCRYPTED_SV2_FRAME_HEADER_SIZE, SV2_FRAME_PLAINTEXT_CHUNK_SIZE,
};
use framing_sv2::framing::{EncodableFrame, HandshakeMessage};
use framing_sv2::SV2_FRAME_CHUNK_SIZE;
use noise_sv2::{
    Initiator, Responder, ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE,
};
use secp256k1::{Keypair, Secp256k1};

use rand::{rngs::StdRng, SeedableRng};

fn generate_key(rand_seed: u64) -> Keypair {
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(rand_seed);

    let (secret_key, _public_key) = secp.generate_keypair(&mut rng);

    Keypair::from_secret_key(&secp, &secret_key)
}

fn read_handshake<R: ExpectsHandshakeMessage>(
    decoder: &mut NoiseDecoder,
    wire: &[u8],
) -> HandshakeMessage {
    let mut offset = 0;
    loop {
        let writable = decoder.read_buf();
        let len = writable.len();
        let n = len.min(wire.len().saturating_sub(offset));
        if n > 0 {
            writable[..n].copy_from_slice(&wire[offset..offset + n]);
            decoder.advance(n).unwrap();
            offset += n;
        }

        match decoder.next_handshake_frame::<R>() {
            Ok(Decoded::Frame(frame)) => return frame,
            Ok(Decoded::Incomplete) => continue,
            Err(e) => panic!("read_handshake failed: {e:?}"),
        }
    }
}

fn transport_halves() -> (
    TransportEncryptState,
    TransportDecryptState,
    TransportEncryptState,
    TransportDecryptState,
) {
    let kp = generate_key(0x5eed);
    let responder_pk = kp.public_key().x_only_public_key().0;

    let mut encoder = NoiseEncoder::new();
    let mut to_responder = NoiseDecoder::new();
    let mut to_initiator = NoiseDecoder::new();

    let (first, initiator) = Handshake::initiator(Initiator::new(Some(responder_pk)))
        .step_0()
        .expect("initiator step 0");
    let first_wire = encoder.encode_handshake(first);
    let first = read_handshake::<Responder>(&mut to_responder, first_wire.as_ref());
    let first: [u8; ELLSWIFT_ENCODING_SIZE] = first.payload().try_into().unwrap();

    let responder = Handshake::responder(Responder::new(kp, 3600));
    let (second, responder_transport) = responder.step_1(first).expect("responder step 1");
    let second_wire = encoder.encode_handshake(second);
    let second = read_handshake::<InitiatorSent>(&mut to_initiator, second_wire.as_ref());
    let second: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
        second.payload().try_into().unwrap();

    let initiator_transport = initiator.step_2(second).expect("initiator step 2");
    let (i_enc, i_dec) = initiator_transport.split();
    let (r_enc, r_dec) = responder_transport.split();
    (i_enc, i_dec, r_enc, r_dec)
}

struct WireFrame(Vec<u8>);

impl EncodableFrame for WireFrame {
    fn encoded_length(&self) -> usize {
        self.0.len()
    }
    fn encode_into(self, dst: &mut [u8]) -> Result<(), framing_sv2::Error> {
        if dst.len() != self.0.len() {
            return Err(framing_sv2::Error::UnexpectedDestinationLength {
                expected: self.0.len(),
                actual: dst.len(),
            });
        }
        dst.copy_from_slice(&self.0);
        Ok(())
    }
}

fn plaintext_frame(ext_type: u16, msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(6 + payload.len());
    frame.extend_from_slice(&ext_type.to_le_bytes());
    frame.push(msg_type);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes()[..3]);
    frame.extend_from_slice(payload);
    frame
}

fn ciphertext_len(payload_len: usize) -> usize {
    22 + payload_len + 16 * payload_len.div_ceil(SV2_FRAME_PLAINTEXT_CHUNK_SIZE)
}

fn decode_wire(
    decoder: &mut NoiseDecoder,
    mut state: TransportDecryptState,
    wire: &[u8],
    seg: u8,
) -> (Vec<CodecSerializedFrame>, Option<TransportDecryptState>) {
    let mut frames = Vec::new();
    let mut offset = 0;
    loop {
        match decoder.next_transport_frame(state) {
            Ok(Decrypted::Frame(frame, next)) => {
                state = next;
                frames.push(frame);
            }
            Ok(Decrypted::Incomplete(next)) => {
                state = next;
                if offset == wire.len() {
                    return (frames, Some(state));
                }
                let rl = decoder.read_len();
                let window = decoder.read_buf();
                assert!(
                    !window.is_empty(),
                    "Incomplete must leave a non-empty window"
                );
                assert!(rl <= SV2_FRAME_CHUNK_SIZE);

                let available = wire.len() - offset;
                let cap = if seg == 0 {
                    window.len()
                } else {
                    1 + (seg as usize % 64)
                };
                let n = window.len().min(available).min(cap);
                window[..n].copy_from_slice(&wire[offset..offset + n]);
                decoder.advance(n).unwrap();
                offset += n;
            }
            Err(_) => return (frames, None),
        }
    }
}

fn build_payload(len: usize, seed: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; len];
    if !seed.is_empty() {
        for i in 0..len {
            v[i] = seed[i % seed.len()];
        }
    }
    v
}

fn payload_len_sel(sel: u8, seed_len: usize) -> usize {
    match sel % 8 {
        0 => 0,
        1 => 1,
        2 => seed_len.min(64),
        3 => seed_len.min(2 * SV2_FRAME_PLAINTEXT_CHUNK_SIZE + 1),
        4 => SV2_FRAME_PLAINTEXT_CHUNK_SIZE - 1,
        5 => SV2_FRAME_PLAINTEXT_CHUNK_SIZE,
        6 => SV2_FRAME_PLAINTEXT_CHUNK_SIZE + 1,
        7 => 2 * SV2_FRAME_PLAINTEXT_CHUNK_SIZE + 1,
        _ => 0,
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let mode = data[0] & 0x07;
    let two_frame = data[0] & 0x80 != 0;
    let direction = (data[0] >> 3) & 1;
    let len_sel = if data.len() > 1 { data[1] } else { 0 };
    let seg_sel = if data.len() > 2 { data[2] } else { 0 };
    let ext_type = if data.len() >= 5 {
        u16::from_le_bytes([data[3], data[4]])
    } else {
        0
    };
    let msg_type = if data.len() >= 6 { data[5] } else { 0 };
    let seed: &[u8] = if data.len() >= 7 { &data[6..] } else { &[] };

    let (i_enc, i_dec, r_enc, r_dec) = transport_halves();
    let (mut enc, mut dec_state) = if direction == 0 {
        (i_enc, r_dec)
    } else {
        (r_enc, i_dec)
    };

    let mut decoder = NoiseDecoder::new();
    let mut encoder = NoiseEncoder::new();

    match mode {
        0 => {
            let plen = payload_len_sel(len_sel, seed.len());
            let payload = build_payload(plen, seed);
            let plain = plaintext_frame(ext_type, msg_type, &payload);

            let n_frames = if two_frame { 2 } else { 1 };
            let plains: Vec<Vec<u8>> = (0..n_frames).map(|_| plain.clone()).collect();

            let mut wire = Vec::new();
            for p in &plains {
                let wf = WireFrame(p.clone());
                let out = encoder
                    .encode_transport(wf, &mut enc)
                    .expect("encode transport");
                let out: &[u8] = out.as_ref();
                assert_eq!(out.len(), ciphertext_len(plen));
                wire.extend_from_slice(out);
            }

            let (decoded, st) = decode_wire(&mut decoder, dec_state, &wire, seg_sel);
            dec_state = st.expect("state after roundtrip decode");
            assert_eq!(decoded.len(), n_frames);
            for (f, p) in decoded.iter().zip(plains.iter()) {
                assert_eq!(f.as_bytes(), p.as_slice());
                assert_eq!(f.header().ext_type(), ext_type);
                assert_eq!(f.header().msg_type(), msg_type);
                assert_eq!(f.header().payload_length(), plen);
            }

            let owned: Vec<CodecSerializedFrame> =
                decoded.into_iter().map(|f| f.into_owned()).collect();
            let mut wire2 = Vec::new();
            for f in owned {
                let out = encoder
                    .encode_transport(f, &mut enc)
                    .expect("re-encode transport");
                let out: &[u8] = out.as_ref();
                wire2.extend_from_slice(out);
            }

            let (decoded2, st2) = decode_wire(&mut decoder, dec_state, &wire2, seg_sel);
            assert!(st2.is_some());
            assert_eq!(decoded2.len(), n_frames);
            for (f, p) in decoded2.iter().zip(plains.iter()) {
                assert_eq!(f.as_bytes(), p.as_slice());
            }
        }
        1 => {
            let plen = payload_len_sel(len_sel, seed.len());
            let payload = build_payload(plen, seed);
            let plain = plaintext_frame(ext_type, msg_type, &payload);
            let wf = WireFrame(plain);
            let out = encoder
                .encode_transport(wf, &mut enc)
                .expect("encode transport");
            let mut wire: Vec<u8> = out.as_ref().to_vec();
            assert!(!wire.is_empty());
            let off = seg_sel as usize % wire.len();
            wire[off] ^= 0xff;

            let (frames, st) = decode_wire(&mut decoder, dec_state, &wire, 0);
            assert!(frames.is_empty());
            assert!(st.is_none());
        }
        2 => {
            let plen = payload_len_sel(len_sel, seed.len());
            let payload = build_payload(plen, seed);
            let plain = plaintext_frame(ext_type, msg_type, &payload);
            let wf = WireFrame(plain);
            let out = encoder
                .encode_transport(wf, &mut enc)
                .expect("encode transport");
            let wire: Vec<u8> = out.as_ref().to_vec();
            if wire.len() <= 1 {
                return;
            }
            let k = (seg_sel as usize % (wire.len() - 1)) + 1;
            let prefix = &wire[..k];

            let (frames, st) = decode_wire(&mut decoder, dec_state, prefix, seg_sel);
            assert!(frames.is_empty());
            assert!(st.is_some());
            assert!(decoder.read_len() > 0);
            assert!(decoder.read_len() <= SV2_FRAME_CHUNK_SIZE);
        }
        3 => {
            let cap = 2 * SV2_FRAME_CHUNK_SIZE + 22;
            let wire: Vec<u8> = if data.len() > cap {
                data[..cap].to_vec()
            } else {
                data.to_vec()
            };

            let (frames, st) = decode_wire(&mut decoder, dec_state, &wire, seg_sel);
            for f in &frames {
                assert_eq!(f.as_bytes().len(), 6 + f.header().payload_length());
            }
            if st.is_some() {
                assert!(decoder.read_len() <= SV2_FRAME_CHUNK_SIZE);
            }
        }
        4 => {
            let declared = match len_sel % 5 {
                0 => 0usize,
                1 => 1usize,
                2 => SV2_FRAME_PLAINTEXT_CHUNK_SIZE,
                3 => SV2_FRAME_PLAINTEXT_CHUNK_SIZE + 1,
                4 => 0xffffffusize,
                _ => 0usize,
            };
            let mut hdr = Vec::with_capacity(6);
            hdr.extend_from_slice(&ext_type.to_le_bytes());
            hdr.push(msg_type);
            hdr.extend_from_slice(&(declared as u32).to_le_bytes()[..3]);
            let wf = WireFrame(hdr);
            let out = encoder
                .encode_transport(wf, &mut enc)
                .expect("encode transport");
            let wire: Vec<u8> = out.as_ref().to_vec();
            let wire = &wire[..ENCRYPTED_SV2_FRAME_HEADER_SIZE.min(wire.len())];

            let (frames, st) = decode_wire(&mut decoder, dec_state, wire, 0);
            if declared == 0 {
                assert_eq!(frames.len(), 1);
                assert_eq!(frames[0].as_bytes().len(), 6);
                assert_eq!(frames[0].header().payload_length(), 0);
            } else {
                assert!(frames.is_empty());
                assert!(st.is_some());
                let expected_rl = declared.min(SV2_FRAME_PLAINTEXT_CHUNK_SIZE) + 16;
                assert_eq!(decoder.read_len(), expected_rl);
            }
        }
        5 => {
            let plen = payload_len_sel(len_sel, seed.len());
            let payload = build_payload(plen, seed);
            let plain = plaintext_frame(ext_type, msg_type, &payload);
            let wf = WireFrame(plain);
            let out = encoder
                .encode_transport(wf, &mut enc)
                .expect("encode transport");
            let mut wire: Vec<u8> = out.as_ref().to_vec();
            let tail_len = 1 + (seg_sel as usize % 64);
            for i in 0..tail_len {
                let b = if seed.is_empty() {
                    0u8
                } else {
                    seed[i % seed.len()]
                };
                wire.push(b);
            }

            let (frames, st) = decode_wire(&mut decoder, dec_state, &wire, seg_sel);
            assert_eq!(frames.len(), 1);
            if tail_len >= 22 {
                assert!(st.is_none());
            } else {
                assert!(st.is_some());
            }
        }
        _ => {}
    }
});
