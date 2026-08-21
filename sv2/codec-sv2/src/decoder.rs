// # Decoder
//
// Provides utilities for decoding messages held by Sv2 frames, with or without Noise protocol
// support.
//
// It includes primitives to both decode encoded standard Sv2 frames and to decrypt and decode
// Noise-encrypted encoded Sv2 frames, ensuring secure communication when required.
//
// ## Usage
// All messages passed between Sv2 roles are encoded as Sv2 frames. These frames are decoded using
// primitives in this module. There are two types of decoders for reading these frames: one for
// regular Sv2 frames [`StandardDecoder`], and another for Noise-encrypted frames
// [`StandardNoiseDecoder`]. Both decoders manage the deserialization of incoming data and, when
// applicable, the decryption of the data upon receiving the transmitted message.
//
// ### Buffer Management
//
// The decoders rely on buffers to hold intermediate data during the decoding process.
//
// - When the `with_buffer_pool` feature is enabled, the internal `Buffer` type is backed by a
//   pool-allocated buffer [`binary_sv2::BufferPool`], providing more efficient memory usage,
//   particularly in high-throughput scenarios.
// - If this feature is not enabled, a system memory buffer [`binary_sv2::BufferFromSystemMemory`]
//   is used for simpler applications where memory efficiency is less critical.

#[cfg(feature = "noise_sv2")]
use binary_sv2::Deserialize;
#[cfg(feature = "noise_sv2")]
use binary_sv2::GetSize;
use binary_sv2::Serialize;
pub use buffer_sv2::AeadBuffer;
use core::marker::PhantomData;
#[cfg(feature = "noise_sv2")]
use framing_sv2::framing::HandShakeFrame;
use framing_sv2::{
    framing::{Frame, SizeHint, Sv2Frame},
    header::Header,
};
#[cfg(feature = "noise_sv2")]
use framing_sv2::{ENCRYPTED_SV2_FRAME_HEADER_SIZE, SV2_FRAME_CHUNK_SIZE, SV2_FRAME_HEADER_SIZE};
#[cfg(feature = "noise_sv2")]
use noise_sv2::NOISE_FRAME_HEADER_SIZE;

use crate::error::{Error, Result};

use crate::Error::MissingBytes;
#[cfg(feature = "noise_sv2")]
use crate::{State, TransportDecryptState};

#[cfg(not(feature = "with_buffer_pool"))]
use buffer_sv2::{Buffer as IsBuffer, BufferFromSystemMemory as Buffer};

#[cfg(feature = "with_buffer_pool")]
use buffer_sv2::{Buffer as IsBuffer, BufferFromSystemMemory, BufferPool};

// The buffer type for holding intermediate data during decoding.
//
// When the `with_buffer_pool` feature is enabled, `Buffer` is a pool-allocated buffer type
// [`BufferPool`], which allows for more efficient memory management. Otherwise, it defaults to
// [`BufferFromSystemMemory`].
//
// `Buffer` is used for storing both serialized Sv2 frames and encrypted Noise data.
#[cfg(feature = "with_buffer_pool")]
type Buffer = BufferPool<BufferFromSystemMemory>;

/// An encoded or decoded Sv2 frame containing either a regular or Noise-protected message.
///
/// A wrapper around the [`Frame`] enum that represents either a regular or Noise-protected Sv2
/// frame containing the generic message type (`T`).
pub type StandardEitherFrame<T> = Frame<T, <Buffer as IsBuffer>::Slice>;

/// An encoded or decoded Sv2 frame.
///
/// A wrapper around the [`Sv2Frame`] that represents a regular Sv2 frame containing the generic
/// message type (`T`).
pub type StandardSv2Frame<T> = Sv2Frame<T, <Buffer as IsBuffer>::Slice>;

/// Standard Sv2 decoder with Noise protocol support.
///
/// Used for decoding and decrypting generic message types (`T`) encoded in Sv2 frames and
/// encrypted via the Noise protocol.
#[cfg(feature = "noise_sv2")]
pub type StandardNoiseDecoder<T> = WithNoise<Buffer, T>;

/// Standard Sv2 decoder without Noise protocol support.
///
/// Used for decoding generic message types (`T`) encoded in Sv2 frames.
pub type StandardDecoder<T> = WithoutNoise<Buffer, T>;

/// Decoder for Sv2 frames with Noise protocol support.
///
/// Accumulates the encrypted data into a dedicated buffer until the entire encrypted frame is
/// received. The Noise protocol is then used to decrypt the accumulated data into another
/// dedicated buffer, converting it back into its original serialized form. This decrypted data is
/// then deserialized into the original Sv2 frame and message format.
#[cfg(feature = "noise_sv2")]
#[derive(Debug)]
pub struct WithNoise<B: IsBuffer, T: Serialize + binary_sv2::GetSize> {
    // Marker for the type of frame being decoded.
    //
    // Used to maintain the generic type (`T`) information of the message payload held by the
    // frame. `T` refers to a type that implements the necessary traits for serialization
    // [`binary_sv2::Serialize`] and size calculation [`binary_sv2::GetSize`].
    frame: PhantomData<T>,

    // Tracks the number of bytes remaining until the full frame is received.
    //
    // Ensures that the full encrypted Noise frame has been received by keeping track of the
    // remaining bytes. Once the complete frame is received, decoding can proceed.
    missing_noise_b: usize,

    // Buffer for holding incoming encrypted Noise data to be decrypted.
    //
    // Stores the incoming encrypted data, allowing the decoder to accumulate the necessary bytes
    // for full decryption. Once the entire encrypted frame is received, the decoder processes the
    // buffer to extract the underlying frame.
    noise_buffer: B,

    // Buffer for holding decrypted data to be decoded.
    //
    // Stores the decrypted data until it is ready to be processed and converted into a Sv2 frame.
    sv2_buffer: B,
}

#[cfg(feature = "noise_sv2")]
impl<'a, T: Serialize + GetSize + Deserialize<'a>, B: IsBuffer + AeadBuffer> WithNoise<B, T> {
    /// Attempts to decode the next Noise encrypted frame.
    ///
    /// On success, the decoded and decrypted frame is returned. Otherwise, an error indicating the
    /// number of missing bytes required to complete the encoded frame, an error on a badly
    /// formatted message header, or an error on decryption failure is returned.
    ///
    /// In this case of the `Error::MissingBytes`, the user should resize the decoder buffer using
    /// `writable`, read another chunk from the incoming message stream, and then call `next_frame`
    /// again. This process should be repeated until `next_frame` returns `Ok`, indicating that the
    /// full message has been received, and the decoding and decryption of the frame can proceed.
    ///
    /// `Error::UnexpectedTrailingBytes` reports bytes buffered past the end of the current frame.
    /// The buffers are drained, but in transport mode the AEAD nonce may already have advanced
    /// for the dropped frame, so the caller must tear down the connection and re-handshake.
    #[inline]
    pub fn next_frame(&mut self, state: &mut State) -> Result<Frame<T, B::Slice>> {
        match state {
            State::HandShake(_) => unreachable!(),
            State::NotInitialized(msg_len) => {
                let buffered = self.noise_buffer.as_ref().len();
                if buffered > *msg_len {
                    return Err(self.reset_after_surplus(buffered - *msg_len, *msg_len));
                }
                let hint = *msg_len - buffered;
                match hint {
                    0 => {
                        self.missing_noise_b = NOISE_FRAME_HEADER_SIZE;
                        Ok(self.while_handshaking())
                    }
                    _ => {
                        self.missing_noise_b = hint;
                        Err(Error::MissingBytes(hint))
                    }
                }
            }
            State::Transport(engine) => {
                self.next_transport(|buf| engine.decrypt(buf).map_err(Into::into))
            }
        }
    }

    /// Attempts to decode the next Noise frame with the decrypting half of a split [`State`].
    #[inline]
    pub fn next_transport_frame(
        &mut self,
        state: &mut TransportDecryptState,
    ) -> Result<Frame<T, B::Slice>> {
        self.next_transport(|buf| state.decrypt(buf))
    }

    // Decodes a transport-mode frame, decrypting through `decrypt`.
    #[inline]
    fn next_transport(
        &mut self,
        decrypt: impl FnMut(&mut B) -> Result<()>,
    ) -> Result<Frame<T, B::Slice>> {
        let hint = if IsBuffer::len(&self.sv2_buffer) < SV2_FRAME_HEADER_SIZE {
            let buffered = IsBuffer::len(&self.noise_buffer);
            if buffered > ENCRYPTED_SV2_FRAME_HEADER_SIZE {
                        return Err(self.reset_after_surplus(
                    buffered - ENCRYPTED_SV2_FRAME_HEADER_SIZE,
                    ENCRYPTED_SV2_FRAME_HEADER_SIZE,
                ));
            }
            ENCRYPTED_SV2_FRAME_HEADER_SIZE - buffered
        } else {
            let src = self.sv2_buffer.get_data_by_ref(SV2_FRAME_HEADER_SIZE);
            let header = Header::from_bytes(src)?;
            let encrypted_len = header.encrypted_len();
                    let buffered = IsBuffer::len(&self.noise_buffer);
                    if buffered > encrypted_len {
                        return Err(self.reset_after_surplus(
                            buffered - encrypted_len,
                            ENCRYPTED_SV2_FRAME_HEADER_SIZE,
                        ));
                    }
                    encrypted_len - buffered
        };

        match hint {
            0 => {
                self.missing_noise_b = ENCRYPTED_SV2_FRAME_HEADER_SIZE;
                self.decode_noise_frame(decrypt)
            }
            _ => {
                self.missing_noise_b = hint;
                Err(Error::MissingBytes(hint))
            }
        }
    }

    fn reset_after_surplus(&mut self, surplus: usize, missing: usize) -> Error {
        let _ = self.noise_buffer.get_data_owned();
        if !IsBuffer::is_empty(&self.sv2_buffer) {
            let _ = self.sv2_buffer.get_data_owned();
        }
        self.missing_noise_b = missing;
        Error::UnexpectedTrailingBytes(surplus)
    }

    /// Returns the number of bytes expected in the next read operation.
    ///
    /// This value indicates how many more bytes are required to complete the
    /// current Noise-encrypted frame. It is used to determine the exact size
    /// of the writable buffer that should be passed to the underlying stream
    /// during reading.
    ///
    /// The returned length dynamically updates as data is received and processed,
    /// and ensures that we only read as much as needed to complete the frame.
    pub fn writable_len(&self) -> usize {
        self.missing_noise_b
    }

    /// Provides a writable buffer for receiving incoming Noise-encrypted Sv2 data.
    ///
    /// This buffer is used to store incoming data, and its size is adjusted based on the number
    /// of missing bytes. As new data is read, it is written into this buffer until enough data has
    /// been received to fully decode a frame. The buffer must have the correct number of bytes
    /// available to progress to the decoding process.
    #[inline]
    pub fn writable(&mut self) -> &mut [u8] {
        self.noise_buffer.get_writable(self.missing_noise_b)
    }

    /// Determines whether the decoder's internal buffers can be safely dropped.
    ///
    /// For more information, refer to the [`buffer_sv2`
    /// crate](https://docs.rs/buffer_sv2/latest/buffer_sv2/).
    pub fn droppable(&self) -> bool {
        self.noise_buffer.is_droppable() && self.sv2_buffer.is_droppable()
    }

    // Processes and decodes a Sv2 frame during the Noise protocol handshake phase.
    //
    // Handles the decoding of a handshake frame from the `noise_buffer`. It converts the received
    // data into a `HandShakeFrame` and encapsulates it into a `Frame` for further processing by
    // the codec.
    //
    // This is used exclusively during the initial handshake phase of the Noise protocol, before
    // transitioning to regular frame encryption and decryption.
    fn while_handshaking(&mut self) -> Frame<T, B::Slice> {
        let src = self.noise_buffer.get_data_owned().as_mut().to_vec();

        // Since the frame length is already validated during the handshake process, this
        // operation is infallible.
        // Conditionally call `.into()` based on `with_buffer_pool` feature to handle differences
        // between Clippy and test builds. See: https://github.com/stratum-mining/stratum/pull/1860#discussion_r2457908851
        #[cfg(feature = "with_buffer_pool")]
        let frame = HandShakeFrame::from_bytes(src.into());

        #[cfg(not(feature = "with_buffer_pool"))]
        let frame = HandShakeFrame::from_bytes(src);

        frame.into()
    }

    // Decodes a Noise-encrypted Sv2 frame, handling both the message header and payload
    // decryption.
    //
    // Processes Noise-encrypted Sv2 frames by first decrypting the header, followed by the
    // payload. If the frame's data is received in chunks, it ensures that decryption occurs
    // incrementally as more encrypted data becomes available. The decrypted data is then stored in
    // the `sv2_buffer`, from which the resulting Sv2 frame is extracted and returned.
    //
    // On success, the decoded frame is returned. Otherwise, an error indicating the number of
    // missing bytes required to complete the encoded frame, an error on a badly formatted message
    // header, or a decryption failure error is returned. If there are still bytes missing to
    // complete the frame, the function will return an `Error::MissingBytes` with the number of
    // additional bytes required to fully decrypt the frame. Once all bytes are available, the
    // decryption process completes and the frame can be successfully decoded.
    #[inline]
    fn decode_noise_frame(
        &mut self,
        decrypt: impl FnMut(&mut B) -> Result<()>,
    ) -> Result<Frame<T, B::Slice>> {
        let result = self.try_decode_noise_frame(decrypt);

        match &result {
            // `MissingBytes` is the normal way out of the header round, so the buffer has to be
            // left exactly as it is.
            Err(Error::MissingBytes(_)) | Ok(_) => {}
            Err(_) => {
                // Not a no-op: the decrypt offset and the plaintext decrypted so far persist across
                // calls, so without this the next frame is decrypted at the failing chunk's offset.
                self.sv2_buffer.danger_set_start(0);
                self.sv2_buffer.get_data_owned();
            }
        }

        result
    }

    #[inline]
    fn try_decode_noise_frame(
        &mut self,
        mut decrypt: impl FnMut(&mut B) -> Result<()>,
    ) -> Result<Frame<T, B::Slice>> {
        match (
            IsBuffer::len(&self.noise_buffer),
            IsBuffer::len(&self.sv2_buffer),
        ) {
            // HERE THE SV2 HEADER IS READY TO BE DECRYPTED
            (ENCRYPTED_SV2_FRAME_HEADER_SIZE, 0) => {
                let src = self.noise_buffer.get_data_owned();
                let decrypted_header = self
                    .sv2_buffer
                    .get_writable(ENCRYPTED_SV2_FRAME_HEADER_SIZE);
                decrypted_header.copy_from_slice(src.as_ref());
                self.sv2_buffer.as_ref();
                decrypt(&mut self.sv2_buffer)?;
                let header =
                    Header::from_bytes(self.sv2_buffer.get_data_by_ref(SV2_FRAME_HEADER_SIZE))?;
                self.missing_noise_b = header.encrypted_len();
                Err(Error::MissingBytes(header.encrypted_len()))
            }
            // HERE THE SV2 PAYLOAD IS READY TO BE DECRYPTED
            _ => {
                // DECRYPT THE PAYLOAD IN CHUNKS
                let encrypted_payload = self.noise_buffer.get_data_owned();
                let encrypted_payload_len = encrypted_payload.as_ref().len();
                let mut start = 0;
                let mut end = if encrypted_payload_len < SV2_FRAME_CHUNK_SIZE {
                    encrypted_payload_len
                } else {
                    SV2_FRAME_CHUNK_SIZE
                };
                // Do not try to decrypt the header cause it is already decrypted
                let mut decrypted_len = SV2_FRAME_HEADER_SIZE;

                while start < encrypted_payload_len {
                    let decrypted_payload = self.sv2_buffer.get_writable(end - start);
                    decrypted_payload.copy_from_slice(&encrypted_payload.as_ref()[start..end]);
                    self.sv2_buffer.danger_set_start(decrypted_len);
                    decrypt(&mut self.sv2_buffer)?;
                    start = end;
                    end = (start + SV2_FRAME_CHUNK_SIZE).min(encrypted_payload_len);
                    decrypted_len += self.sv2_buffer.as_ref().len();
                }
                self.sv2_buffer.danger_set_start(0);
                let src = self.sv2_buffer.get_data_owned();
                let frame = Sv2Frame::<T, B::Slice>::from_bytes_unchecked(src);
                Ok(frame.into())
            }
        }
    }
}

#[cfg(feature = "noise_sv2")]
impl<T: Serialize + binary_sv2::GetSize> WithNoise<Buffer, T> {
    /// Crates a new [`WithNoise`] decoder with default buffer sizes.
    ///
    /// Initializes the decoder with default buffer sizes and sets the number of missing bytes to
    /// 0.
    pub fn new() -> Self {
        Self {
            frame: PhantomData,
            missing_noise_b: 0,
            noise_buffer: Buffer::new(2_usize.pow(16) * 5),
            sv2_buffer: Buffer::new(2_usize.pow(16) * 5),
        }
    }
}

#[cfg(feature = "noise_sv2")]
impl<T: Serialize + binary_sv2::GetSize> Default for WithNoise<Buffer, T> {
    fn default() -> Self {
        Self::new()
    }
}

/// Decoder for standard Sv2 frames.
///
/// Accumulates the data into a dedicated buffer until the entire Sv2 frame is received. This data
/// is then deserialized into the original Sv2 frame and message format.
#[derive(Debug)]
pub struct WithoutNoise<B: IsBuffer, T: Serialize + binary_sv2::GetSize> {
    // Marker for the type of frame being decoded.
    //
    // Used to maintain the generic type (`T`) information of the message payload held by the
    // frame. `T` refers to a type that implements the necessary traits for serialization
    // [`binary_sv2::Serialize`] and size calculation [`binary_sv2::GetSize`].
    frame: PhantomData<T>,

    // Tracks the number of bytes remaining until the full frame is received.
    //
    // Ensures that the full Sv2 frame has been received by keeping track of the remaining bytes.
    // Once the complete frame is received, decoding can proceed.
    missing_b: usize,

    // Buffer for holding incoming data to be decoded into a Sv2 frame.
    //
    // This buffer stores incoming data as it is received, allowing the decoder to accumulate the
    // necessary bytes until a full frame is available. Once the full encoded frame has been
    // received, the buffer's contents are processed and decoded into an Sv2 frame.
    buffer: B,
}

impl<T: Serialize + binary_sv2::GetSize, B: IsBuffer> WithoutNoise<B, T> {
    /// Attempts to decode the next frame, returning either a frame or an error describing how the
    /// buffered bytes differ from the frame size declared by the header.
    ///
    /// `Error::MissingBytes` carries the number of bytes still required (until a full header has
    /// been buffered, only the bytes needed to complete the header): resize the decoder buffer
    /// using `writable`, read another chunk from the stream, and call `next_frame` again until it
    /// returns `Ok`.
    ///
    /// `Error::UnexpectedTrailingBytes` reports bytes buffered past the end of the frame. The
    /// buffer is drained — including the complete frame that preceded the surplus — so the caller
    /// must resynchronize the stream or reconnect.
    #[inline]
    pub fn next_frame(&mut self) -> Result<Sv2Frame<T, B::Slice>> {
        let len = self.buffer.len();
        let src = self.buffer.get_data_by_ref(len);

        match Sv2Frame::<T, B::Slice>::size_hint(src) {
            SizeHint::Exact => {
                self.missing_b = Header::SIZE;
                let src = self.buffer.get_data_owned();
                let frame = Sv2Frame::<T, B::Slice>::from_bytes_unchecked(src);
                Ok(frame)
            }
            SizeHint::Missing(missing) => {
                self.missing_b = missing;
                Err(MissingBytes(self.missing_b))
            }
            SizeHint::Surplus(surplus) => {
                self.missing_b = Header::SIZE;
                let _ = self.buffer.get_data_owned();
                Err(Error::UnexpectedTrailingBytes(surplus))
            }
        }
    }

    /// Provides a writable buffer for receiving incoming Sv2 data.
    ///
    /// This buffer is used to store incoming data, and its size is adjusted based on the number of
    /// missing bytes. As new data is read, it is written into this buffer until enough data has
    /// been received to fully decode a frame. The buffer must have the correct number of bytes
    /// available to progress to the decoding process.
    pub fn writable(&mut self) -> &mut [u8] {
        self.buffer.get_writable(self.missing_b)
    }
}

impl<T: Serialize + binary_sv2::GetSize> WithoutNoise<Buffer, T> {
    /// Creates a new [`WithoutNoise`] with a buffer of default size.
    ///
    /// Initializes the decoder with a default buffer size and sets the number of missing bytes to
    /// the size of the header.
    pub fn new() -> Self {
        Self {
            frame: PhantomData,
            missing_b: Header::SIZE,
            buffer: Buffer::new(2_usize.pow(16) * 5),
        }
    }
}

impl<T: Serialize + binary_sv2::GetSize> Default for WithoutNoise<Buffer, T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use binary_sv2::Serialize;

    #[derive(Serialize)]
    pub struct TestMessage {}

    #[test]
    fn unencrypted_writable_with_missing_b_initialized_as_header_size() {
        let mut decoder = StandardDecoder::<TestMessage>::new();
        let actual = decoder.writable();
        let expect = [0u8; Header::SIZE];
        assert_eq!(actual, expect);
    }
}

#[cfg(test)]
mod prop_tests {
    use crate::{decoder::Buffer, encoder::Encoder, StandardDecoder};
    #[cfg(feature = "noise_sv2")]
    use crate::{HandshakeRole, NoiseEncoder, StandardNoiseDecoder, State};
    use binary_sv2::{Deserialize, Serialize};
    use buffer_sv2::Buffer as IsBuffer;
    #[cfg(feature = "noise_sv2")]
    use framing_sv2::framing::Frame;
    use framing_sv2::{framing::Sv2Frame, header::Header};
    #[cfg(feature = "noise_sv2")]
    use key_utils::{Secp256k1PublicKey, Secp256k1SecretKey};
    #[cfg(feature = "noise_sv2")]
    use noise_sv2::{ELLSWIFT_ENCODING_SIZE, INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE};
    use quickcheck::{Arbitrary, Gen, TestResult};
    use quickcheck_macros::quickcheck;
    #[cfg(feature = "noise_sv2")]
    use std::convert::TryInto;
    #[cfg(feature = "noise_sv2")]
    use std::time::Duration;

    #[cfg(feature = "noise_sv2")]
    const AUTHORITY_PUBLIC_K: &str = "9auqWEzQDVyd2oe1JVGFLMLHZtCo2FFqZwtKA5gd9xbuEu7PH72";
    #[cfg(feature = "noise_sv2")]
    const AUTHORITY_PRIVATE_K: &str = "mkDLTBBRxdBv998612qipDYoTK3YUrqLe8uWw7gu3iXbSrn2n";

    type Slice = <Buffer as IsBuffer>::Slice;

    #[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
    struct TestMessage {
        value: u16,
    }

    impl Arbitrary for TestMessage {
        fn arbitrary(g: &mut Gen) -> Self {
            TestMessage {
                value: u16::arbitrary(g),
            }
        }
    }

    fn decode_frame(
        decoder: &mut StandardDecoder<TestMessage>,
        encoded_bytes: &[u8],
        chunk_size: Option<usize>,
    ) -> Option<framing_sv2::framing::Sv2Frame<TestMessage, Slice>> {
        let mut offset = 0;
        while offset < encoded_bytes.len() {
            let writable = decoder.writable();
            let available = encoded_bytes.len() - offset;
            let to_copy = match chunk_size {
                Some(c) => core::cmp::min(core::cmp::min(writable.len(), c), available),
                None => core::cmp::min(writable.len(), available),
            };
            writable[..to_copy].copy_from_slice(&encoded_bytes[offset..offset + to_copy]);
            offset += to_copy;

            match decoder.next_frame() {
                Ok(frame) => return Some(frame),
                Err(crate::Error::MissingBytes(_)) => continue,
                Err(_) => return None,
            }
        }
        None
    }

    /// Verifies that encoding then decoding a frame over the standard (unencrypted) codec
    /// recovers the original message, msg_type, and ext_type exactly.
    #[quickcheck]
    fn prop_encode_decode_roundtrip(msg: TestMessage, msg_type: u8, ext_type: u16) -> TestResult {
        let original_msg = msg.clone();

        let frame =
            match Sv2Frame::<TestMessage, Slice>::from_message(msg, msg_type, ext_type, false) {
                Some(f) => f,
                None => return TestResult::discard(),
            };

        let expected_ext_type = frame.get_header().unwrap().ext_type();

        let mut encoder = Encoder::<TestMessage>::new();
        let encoded = match encoder.encode(frame) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardDecoder::<TestMessage>::new();
        match decode_frame(&mut decoder, encoded.as_ref(), None) {
            Some(mut decoded_frame) => {
                let header = match decoded_frame.get_header() {
                    Some(h) => h,
                    None => return TestResult::failed(),
                };
                let actual_msg_type = header.msg_type();
                let actual_ext_type = header.ext_type();
                let decoded_msg: TestMessage = match binary_sv2::from_bytes(decoded_frame.payload())
                {
                    Ok(m) => m,
                    Err(_) => return TestResult::failed(),
                };
                TestResult::from_bool(
                    decoded_msg == original_msg
                        && actual_msg_type == msg_type
                        && actual_ext_type == expected_ext_type,
                )
            }
            None => TestResult::failed(),
        }
    }

    /// Verifies that the decoder correctly accumulates partial input, emitting `MissingBytes`
    /// on each incomplete delivery before returning the frame once all bytes arrive.
    #[quickcheck]
    fn prop_decoder_handles_partial_data(
        msg: TestMessage,
        msg_type: u8,
        chunk_size: u8,
    ) -> TestResult {
        if chunk_size == 0 {
            return TestResult::discard();
        }

        let frame = match Sv2Frame::<TestMessage, Slice>::from_message(msg, msg_type, 0, false) {
            Some(f) => f,
            None => return TestResult::discard(),
        };

        let mut encoder = Encoder::<TestMessage>::new();
        let encoded = match encoder.encode(frame) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardDecoder::<TestMessage>::new();
        let encoded_bytes: &[u8] = encoded.as_ref();
        let chunk_size = (chunk_size as usize).max(1);

        let mut offset = 0;
        let mut missing_bytes_count = 0;
        while offset < encoded_bytes.len() {
            let writable = decoder.writable();
            let to_copy = core::cmp::min(
                core::cmp::min(writable.len(), chunk_size),
                encoded_bytes.len() - offset,
            );
            writable[..to_copy].copy_from_slice(&encoded_bytes[offset..offset + to_copy]);
            offset += to_copy;

            match decoder.next_frame() {
                Ok(_) => return TestResult::passed(),
                Err(crate::Error::MissingBytes(n)) => {
                    missing_bytes_count += 1;
                    assert!(n > 0);
                }
                Err(_) => return TestResult::failed(),
            }
        }

        TestResult::from_bool(missing_bytes_count > 0)
    }

    /// Verifies that over-filling the buffer (calling `writable` twice before `next_frame`)
    /// surfaces `UnexpectedTrailingBytes`, drains the buffer, and leaves the decoder usable.
    #[test]
    fn test_decoder_excess_bytes_drains_and_recovers() {
        let msg = TestMessage { value: 42 };
        let frame = Sv2Frame::<TestMessage, Slice>::from_message(msg.clone(), 0, 0, false).unwrap();
        let mut encoder = Encoder::<TestMessage>::new();
        let encoded = encoder.encode(frame).unwrap();
        let encoded: &[u8] = encoded.as_ref();

        let mut decoder = StandardDecoder::<TestMessage>::new();
        decoder.writable().copy_from_slice(&encoded[..Header::SIZE]);
        assert!(matches!(
            decoder.next_frame(),
            Err(crate::Error::MissingBytes(_))
        ));
        decoder.writable().copy_from_slice(&encoded[Header::SIZE..]);

        // Write past the slice `writable` returned.
        const SURPLUS: usize = 4;
        decoder
            .buffer
            .get_writable(SURPLUS)
            .copy_from_slice(&[0xff; SURPLUS]);

        match decoder.next_frame() {
            Err(crate::Error::UnexpectedTrailingBytes(n)) => assert_eq!(n, SURPLUS),
            Ok(_) => panic!("expected UnexpectedTrailingBytes, got a frame"),
            Err(e) => panic!("expected UnexpectedTrailingBytes, got {e:?}"),
        }

        let mut decoded =
            decode_frame(&mut decoder, encoded, None).expect("decoder should recover");
        let decoded_msg: TestMessage = binary_sv2::from_bytes(decoded.payload()).unwrap();
        assert_eq!(decoded_msg, msg);
    }

    /// Verifies that over-filling the noise buffer (writing past the slice returned by
    /// `writable`) surfaces `UnexpectedTrailingBytes` rather than underflowing the
    /// `missing_noise_b` arithmetic, in the handshake state and in both transport phases
    /// (encrypted header pending, payload pending).
    #[cfg(feature = "noise_sv2")]
    #[test]
    fn test_noise_decoder_excess_bytes_do_not_underflow() {
        const SURPLUS: usize = 4;
        const MSG_LEN: usize = 32;

        // Handshake state.
        let mut state = State::NotInitialized(MSG_LEN);
        let mut decoder = StandardNoiseDecoder::<TestMessage>::new();
        assert!(matches!(
            decoder.next_frame(&mut state),
            Err(crate::Error::MissingBytes(MSG_LEN))
        ));
        decoder.writable().fill(0);
        decoder
            .noise_buffer
            .get_writable(SURPLUS)
            .copy_from_slice(&[0xff; SURPLUS]);
        match decoder.next_frame(&mut state) {
            Err(crate::Error::UnexpectedTrailingBytes(n)) => assert_eq!(n, SURPLUS),
            other => panic!("expected UnexpectedTrailingBytes, got {other:?}"),
        }
        assert_eq!(decoder.writable_len(), MSG_LEN);
        decoder.writable().fill(0);
        assert!(decoder.next_frame(&mut state).is_ok());

        // Transport state, before the encrypted header has been decrypted.
        let (_, mut receiver) = make_transport_state_pair();
        let mut decoder = StandardNoiseDecoder::<TestMessage>::new();
        assert!(matches!(
            decoder.next_frame(&mut receiver),
            Err(crate::Error::MissingBytes(_))
        ));
        decoder.writable().fill(0);
        decoder
            .noise_buffer
            .get_writable(SURPLUS)
            .copy_from_slice(&[0xff; SURPLUS]);
        match decoder.next_frame(&mut receiver) {
            Err(crate::Error::UnexpectedTrailingBytes(n)) => assert_eq!(n, SURPLUS),
            other => panic!("expected UnexpectedTrailingBytes, got {other:?}"),
        }

        // Transport state, once the encrypted header has been decrypted.
        let (mut sender, mut receiver) = make_transport_state_pair();
        let sv2_frame =
            Sv2Frame::<TestMessage, Slice>::from_message(TestMessage { value: 42 }, 0, 0, false)
                .unwrap();
        let mut encoder = NoiseEncoder::<TestMessage>::new();
        let encrypted = encoder.encode(Frame::Sv2(sv2_frame), &mut sender).unwrap();
        let encrypted: &[u8] = encrypted.as_ref();

        let mut decoder = StandardNoiseDecoder::<TestMessage>::new();
        let mut offset = 0;
        // Two rounds: prime the encrypted header size, then feed the encrypted header.
        for _ in 0..2 {
            let w = decoder.writable();
            let n = w.len().min(encrypted.len() - offset);
            w[..n].copy_from_slice(&encrypted[offset..offset + n]);
            offset += n;
            assert!(matches!(
                decoder.next_frame(&mut receiver),
                Err(crate::Error::MissingBytes(_))
            ));
        }

        // The decoder now wants the payload: write it, then over-fill.
        let w = decoder.writable();
        let n = w.len().min(encrypted.len() - offset);
        w[..n].copy_from_slice(&encrypted[offset..offset + n]);
        decoder
            .noise_buffer
            .get_writable(SURPLUS)
            .copy_from_slice(&[0xff; SURPLUS]);
        match decoder.next_frame(&mut receiver) {
            Err(crate::Error::UnexpectedTrailingBytes(n)) => assert_eq!(n, SURPLUS),
            other => panic!("expected UnexpectedTrailingBytes, got {other:?}"),
        }
    }

    /// Verifies that a single decoder instance correctly decodes two consecutive independent
    /// frames in sequence, confirming that internal state resets between frames.
    #[quickcheck]
    fn prop_decoder_multiple_frames(
        msg1: TestMessage,
        msg2: TestMessage,
        msg_type: u8,
    ) -> TestResult {
        let frame1 =
            match Sv2Frame::<TestMessage, Slice>::from_message(msg1.clone(), msg_type, 0, false) {
                Some(f) => f,
                None => return TestResult::discard(),
            };
        let frame2 =
            match Sv2Frame::<TestMessage, Slice>::from_message(msg2.clone(), msg_type, 0, false) {
                Some(f) => f,
                None => return TestResult::discard(),
            };

        let mut encoder = Encoder::<TestMessage>::new();
        let encoded1 = match encoder.encode(frame1) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };
        let encoded2 = match encoder.encode(frame2) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardDecoder::<TestMessage>::new();

        let decoded_msg1 = match decode_frame(&mut decoder, encoded1.as_ref(), None) {
            Some(mut f) => match binary_sv2::from_bytes::<TestMessage>(f.payload()) {
                Ok(m) => m,
                Err(_) => return TestResult::failed(),
            },
            None => return TestResult::failed(),
        };
        let decoded_msg2 = match decode_frame(&mut decoder, encoded2.as_ref(), None) {
            Some(mut f) => match binary_sv2::from_bytes::<TestMessage>(f.payload()) {
                Ok(m) => m,
                Err(_) => return TestResult::failed(),
            },
            None => return TestResult::failed(),
        };

        TestResult::from_bool(decoded_msg1 == msg1 && decoded_msg2 == msg2)
    }

    #[cfg(feature = "noise_sv2")]
    fn make_transport_state_pair() -> (State, State) {
        let pub_k: Secp256k1PublicKey = AUTHORITY_PUBLIC_K.to_string().try_into().unwrap();
        let pub_k_bytes = pub_k.into_bytes();
        let priv_k: Secp256k1SecretKey = AUTHORITY_PRIVATE_K.to_string().try_into().unwrap();
        let priv_k_bytes = priv_k.into_bytes();

        let initiator = noise_sv2::Initiator::from_raw_k(pub_k_bytes).unwrap();
        let responder = noise_sv2::Responder::from_authority_kp(
            &pub_k_bytes,
            &priv_k_bytes,
            Duration::from_secs(3600),
        )
        .unwrap();

        let mut sender_state = State::initialized(HandshakeRole::Initiator(initiator));
        let mut receiver_state = State::initialized(HandshakeRole::Responder(responder));

        let msg0 = sender_state.step_0().unwrap();
        let msg0: [u8; ELLSWIFT_ENCODING_SIZE] =
            msg0.get_payload_when_handshaking().try_into().unwrap();

        let (msg1, receiver_transport) = receiver_state.step_1(msg0).unwrap();
        let msg1: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] =
            msg1.get_payload_when_handshaking().try_into().unwrap();

        let sender_transport = sender_state.step_2(msg1).unwrap();
        let sender_state = match sender_transport {
            State::Transport(c) => State::with_transport_mode(c),
            _ => unreachable!(),
        };
        let receiver_state = match receiver_transport {
            State::Transport(c) => State::with_transport_mode(c),
            _ => unreachable!(),
        };
        (sender_state, receiver_state)
    }

    #[cfg(feature = "noise_sv2")]
    fn decode_noise_frame(
        decoder: &mut StandardNoiseDecoder<TestMessage>,
        state: &mut State,
        encoded: &[u8],
    ) -> Option<Sv2Frame<TestMessage, Slice>> {
        let mut offset = 0;
        loop {
            let writable = decoder.writable();
            let available = encoded.len().saturating_sub(offset);
            let n = writable.len().min(available);
            writable[..n].copy_from_slice(&encoded[offset..offset + n]);
            offset += n;

            match decoder.next_frame(state) {
                Ok(Frame::Sv2(frame)) => return Some(frame),
                Ok(_) => return None,
                Err(crate::Error::MissingBytes(_)) => {}
                Err(_) => return None,
            }
        }
    }

    /// Verifies that encrypting then decrypting a frame via `NoiseEncoder`
    /// recovers the original message, msg_type, and ext_type exactly.
    #[cfg(feature = "noise_sv2")]
    #[quickcheck]
    fn prop_noise_encode_decode_roundtrip(
        msg: TestMessage,
        msg_type: u8,
        ext_type: u16,
    ) -> TestResult {
        let (mut sender_state, mut receiver_state) = make_transport_state_pair();
        let original = msg.clone();

        let sv2_frame =
            match Sv2Frame::<TestMessage, Slice>::from_message(msg, msg_type, ext_type, false) {
                Some(f) => f,
                None => return TestResult::discard(),
            };
        let expected_ext = sv2_frame.get_header().unwrap().ext_type();
        let frame = Frame::Sv2(sv2_frame);

        let mut encoder = NoiseEncoder::<TestMessage>::new();
        let encrypted = match encoder.encode(frame, &mut sender_state) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardNoiseDecoder::<TestMessage>::new();
        let encrypted_bytes: &[u8] = encrypted.as_ref();
        match decode_noise_frame(&mut decoder, &mut receiver_state, encrypted_bytes) {
            Some(mut decoded) => {
                let header = match decoded.get_header() {
                    Some(h) => h,
                    None => return TestResult::failed(),
                };
                let decoded_msg: TestMessage = match binary_sv2::from_bytes(decoded.payload()) {
                    Ok(m) => m,
                    Err(_) => return TestResult::failed(),
                };
                TestResult::from_bool(
                    decoded_msg == original
                        && header.msg_type() == msg_type
                        && header.ext_type() == expected_ext,
                )
            }
            None => TestResult::failed(),
        }
    }

    /// Verifies that `StandardNoiseDecoder` correctly handles data arriving in multiple rounds —
    /// one round per encrypted segment (header, then payload) — emitting `MissingBytes`
    /// between rounds before returning the fully decrypted frame.
    #[cfg(feature = "noise_sv2")]
    #[quickcheck]
    fn prop_noise_decoder_handles_partial_data(msg: TestMessage, msg_type: u8) -> TestResult {
        let frame = match Sv2Frame::<TestMessage, Slice>::from_message(msg, msg_type, 0, false) {
            Some(f) => Frame::Sv2(f),
            None => return TestResult::discard(),
        };

        let (mut sender_state, mut receiver_state) = make_transport_state_pair();
        let mut encoder = NoiseEncoder::<TestMessage>::new();
        let encrypted = match encoder.encode(frame, &mut sender_state) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardNoiseDecoder::<TestMessage>::new();
        let encoded_bytes: &[u8] = encrypted.as_ref();
        let mut offset = 0;
        let mut missing_bytes_count = 0;

        loop {
            let writable = decoder.writable();
            let n = writable
                .len()
                .min(encoded_bytes.len().saturating_sub(offset));
            writable[..n].copy_from_slice(&encoded_bytes[offset..offset + n]);
            offset += n;

            match decoder.next_frame(&mut receiver_state) {
                Ok(_) => return TestResult::from_bool(missing_bytes_count > 0),
                Err(crate::Error::MissingBytes(n)) => {
                    missing_bytes_count += 1;
                    assert!(n > 0);
                }
                Err(_) => return TestResult::failed(),
            }
        }
    }

    #[cfg(feature = "noise_sv2")]
    #[test]
    fn noise_decoder_recovers_from_a_failed_decryption() {
        let (mut sender_state, mut receiver_state) = make_transport_state_pair();
        let frame = Frame::Sv2(
            Sv2Frame::<TestMessage, Slice>::from_message(TestMessage { value: 7 }, 0, 0, false)
                .unwrap(),
        );
        let mut encoder = NoiseEncoder::<TestMessage>::new();
        let encrypted = encoder.encode(frame, &mut sender_state).unwrap();
        let encrypted: &[u8] = encrypted.as_ref();

        let mut decoder = StandardNoiseDecoder::<TestMessage>::new();

        // Fail on the encrypted header. The closure never touches `receiver_state`, so its nonce
        // stays where it was and the same bytes can be replayed below.
        let hint = decoder
            .next_transport(|_| Err(crate::Error::UnexpectedNoiseState))
            .unwrap_err();
        assert!(matches!(hint, crate::Error::MissingBytes(_)));
        let writable = decoder.writable();
        let len = writable.len();
        writable.copy_from_slice(&encrypted[..len]);
        let failed = decoder
            .next_transport(|_| Err(crate::Error::UnexpectedNoiseState))
            .unwrap_err();
        assert!(matches!(failed, crate::Error::UnexpectedNoiseState));
        assert_eq!(IsBuffer::len(&decoder.sv2_buffer), 0);
        assert!(decoder.sv2_buffer.as_ref().is_empty());

        // The same decoder must now decode the frame from the start.
        let decoded = decode_noise_frame(&mut decoder, &mut receiver_state, encrypted);
        match decoded {
            Some(mut f) => assert_eq!(
                binary_sv2::from_bytes::<TestMessage>(f.payload()).unwrap(),
                TestMessage { value: 7 }
            ),
            None => panic!("failed to decode the frame after a failed decryption"),
        }
    }

    /// Verifies that a single `StandardNoiseDecoder` instance correctly
    /// decodes two consecutive noise-encrypted frames in sequence using
    /// the same shared transport state.
    #[cfg(feature = "noise_sv2")]
    #[quickcheck]
    fn prop_noise_decoder_multiple_frames(
        msg1: TestMessage,
        msg2: TestMessage,
        msg_type: u8,
    ) -> TestResult {
        let (mut sender_state, mut receiver_state) = make_transport_state_pair();

        let frame1 =
            match Sv2Frame::<TestMessage, Slice>::from_message(msg1.clone(), msg_type, 0, false) {
                Some(f) => Frame::Sv2(f),
                None => return TestResult::discard(),
            };
        let frame2 =
            match Sv2Frame::<TestMessage, Slice>::from_message(msg2.clone(), msg_type, 0, false) {
                Some(f) => Frame::Sv2(f),
                None => return TestResult::discard(),
            };

        let mut encoder = NoiseEncoder::<TestMessage>::new();

        let enc1 = match encoder.encode(frame1, &mut sender_state) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };
        let enc2 = match encoder.encode(frame2, &mut sender_state) {
            Ok(e) => e,
            Err(_) => return TestResult::failed(),
        };

        let mut decoder = StandardNoiseDecoder::<TestMessage>::new();

        let decoded_msg1 =
            match decode_noise_frame(&mut decoder, &mut receiver_state, enc1.as_ref()) {
                Some(mut f) => match binary_sv2::from_bytes::<TestMessage>(f.payload()) {
                    Ok(m) => m,
                    Err(_) => return TestResult::failed(),
                },
                None => return TestResult::failed(),
            };

        let decoded_msg2 =
            match decode_noise_frame(&mut decoder, &mut receiver_state, enc2.as_ref()) {
                Some(mut f) => match binary_sv2::from_bytes::<TestMessage>(f.payload()) {
                    Ok(m) => m,
                    Err(_) => return TestResult::failed(),
                },
                None => return TestResult::failed(),
            };

        TestResult::from_bool(decoded_msg1 == msg1 && decoded_msg2 == msg2)
    }
}
