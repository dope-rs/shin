use crate::crypto::hash::Digest;
use zeroize::Zeroize;

/// Server phase carrying the traffic secret or Finished verifier required by
/// its next input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    ExpectClientHello,
    ExpectEndOfEarlyData { client_handshake_traffic: Digest },
    ExpectClientCertificate { client_handshake_traffic: Digest },
    ExpectClientCertVerify { client_handshake_traffic: Digest },
    ExpectClientFinished { verify_data: Digest },
    Done,
}

impl State {
    pub(super) fn zeroize_secrets(&mut self) {
        match self {
            Self::ExpectEndOfEarlyData {
                client_handshake_traffic,
            }
            | Self::ExpectClientCertificate {
                client_handshake_traffic,
            }
            | Self::ExpectClientCertVerify {
                client_handshake_traffic,
            } => client_handshake_traffic.as_mut_slice().zeroize(),
            Self::ExpectClientFinished { verify_data } => verify_data.as_mut_slice().zeroize(),
            Self::ExpectClientHello | Self::Done => {}
        }
    }
}
