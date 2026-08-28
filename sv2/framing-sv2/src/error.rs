//! # Error Handling
//!
//! This module defines error types and utilities for handling errors in the `framing_sv2` module.

use core::fmt;

use crate::SV2_FRAME_HEADER_SIZE;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Binary Sv2 data format error.
    BinarySv2Error(binary_sv2::Error),
    ExpectedHandshakeFrame,
    ExpectedSv2Frame,
    MissingHeader,
    UnexpectedHeaderLength(isize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            BinarySv2Error(ref e) => {
                write!(f, "BinarySv2Error: `{e}`")
            }
            ExpectedHandshakeFrame => {
                write!(f, "Expected `HandshakeFrame`, received `Sv2Frame`")
            }
            ExpectedSv2Frame => {
                write!(f, "Expected `Sv2Frame`, received `HandshakeFrame`")
            }
            MissingHeader => {
                write!(
                    f,
                    "Frame is missing a header. All frames (Handshake or Sv2) must have a header"
                )
            }
            UnexpectedHeaderLength(actual_size) => {
                write!(
                    f,
                    "Unexpected `Header` length: `{actual_size}`, should be equal or more to {SV2_FRAME_HEADER_SIZE}"
                )
            }
        }
    }
}

impl From<binary_sv2::Error> for Error {
    fn from(e: binary_sv2::Error) -> Self {
        Error::BinarySv2Error(e)
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use alloc::{string::ToString, vec};

    // `ValueExceedsMaxSize` carries a peer-derived sample and this error is logged, so no
    // formatting path may write that sample out.
    #[test]
    fn binary_error_display_does_not_dump_embedded_payload() {
        let sample = vec![0xAB_u8; 64 * 1024];
        let err = Error::BinarySv2Error(binary_sv2::Error::ValueExceedsMaxSize(
            false,
            1,
            1,
            32,
            sample,
            64 * 1024,
        ));

        let rendered = err.to_string();

        assert!(
            !rendered.contains("171"),
            "Display leaked sample bytes: {rendered}"
        );
        assert!(
            rendered.len() < 128,
            "Display grew with the sample: {} bytes",
            rendered.len()
        );
    }
}
