use crate::crypto::hash;
use crate::crypto::ticket;
use crate::transport;
use o3::collections::fixed::array;

const TRANSPORT_PARAMS_HASH_LEN: usize = hash::SHA256_LEN;
const LEGACY_FORMAT_VERSION: u8 = 1;
const FORMAT_VERSION: u8 = 2;

/// Authenticated policy captured when a server issues a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    transport_mode: transport::Mode,
    max_early_data: Option<u32>,
    transport_params_hash: [u8; TRANSPORT_PARAMS_HASH_LEN],
    replay_domain: Option<[u8; ticket::REPLAY_DOMAIN_LEN]>,
}

impl Context {
    pub fn new(
        transport_mode: transport::Mode,
        max_early_data: Option<u32>,
        server_transport_params: &[u8],
    ) -> Self {
        let digest = hash::Algorithm::Sha256.hash(server_transport_params);
        let mut transport_params_hash = [0u8; TRANSPORT_PARAMS_HASH_LEN];
        transport_params_hash.copy_from_slice(digest.as_slice());
        Self {
            transport_mode,
            max_early_data,
            transport_params_hash,
            replay_domain: Some([0; ticket::REPLAY_DOMAIN_LEN]),
        }
    }

    pub fn new_with_replay_domain(
        transport_mode: transport::Mode,
        max_early_data: Option<u32>,
        server_transport_params: &[u8],
        replay_domain: [u8; ticket::REPLAY_DOMAIN_LEN],
    ) -> Self {
        let mut context = Self::new(transport_mode, max_early_data, server_transport_params);
        context.replay_domain = Some(replay_domain);
        context
    }

    pub fn transport_mode(self) -> transport::Mode {
        self.transport_mode
    }

    pub fn max_early_data(self) -> Option<u32> {
        self.max_early_data
    }

    pub fn replay_domain(self) -> Option<[u8; ticket::REPLAY_DOMAIN_LEN]> {
        self.replay_domain
    }

    /// Returns the allowance only for the issued transport and parameters.
    pub fn early_data_for(
        self,
        transport_mode: transport::Mode,
        server_transport_params: &[u8],
    ) -> Option<u32> {
        self.early_data_for_replay_domain(
            transport_mode,
            server_transport_params,
            &[0; ticket::REPLAY_DOMAIN_LEN],
        )
    }

    /// Returns the allowance only in its authenticated replay namespace.
    pub fn early_data_for_replay_domain(
        self,
        transport_mode: transport::Mode,
        server_transport_params: &[u8],
        replay_domain: &[u8; ticket::REPLAY_DOMAIN_LEN],
    ) -> Option<u32> {
        let maximum = self.max_early_data?;
        if self.replay_domain.as_ref() != Some(replay_domain)
            || self.transport_mode != transport_mode
            || !Self::valid_allowance(transport_mode, maximum)
        {
            return None;
        }
        let current = Self::new(transport_mode, None, server_transport_params);
        (self.transport_params_hash == current.transport_params_hash).then_some(maximum)
    }

    pub(super) fn encode<const N: usize>(
        self,
        out: &mut array::CopyInline<u8, N>,
    ) -> Result<(), ticket::Error> {
        out.push(FORMAT_VERSION)
            .map_err(|_| ticket::Error::BadFormat)?;
        out.push(match self.transport_mode {
            transport::Mode::Tls => 0,
            transport::Mode::Quic => 1,
        })
        .map_err(|_| ticket::Error::BadFormat)?;
        let (present, maximum) = match self.max_early_data {
            Some(maximum) if Self::valid_allowance(self.transport_mode, maximum) => (1, maximum),
            Some(_) => return Err(ticket::Error::BadFormat),
            None => (0, 0),
        };
        out.push(present).map_err(|_| ticket::Error::BadFormat)?;
        out.try_extend_from_slice(&maximum.to_be_bytes())
            .map_err(|_| ticket::Error::BadFormat)?;
        out.try_extend_from_slice(&self.transport_params_hash)
            .map_err(|_| ticket::Error::BadFormat)?;
        out.try_extend_from_slice(&self.replay_domain.ok_or(ticket::Error::BadFormat)?)
            .map_err(|_| ticket::Error::BadFormat)
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, ticket::Error> {
        let (expected_len, replay_domain) = match encoded.first().copied() {
            Some(LEGACY_FORMAT_VERSION) => (ticket::LEGACY_CONTEXT_LEN, None),
            Some(FORMAT_VERSION) => (ticket::CONTEXT_LEN, Some(())),
            _ => return Err(ticket::Error::BadFormat),
        };
        if encoded.len() != expected_len {
            return Err(ticket::Error::BadFormat);
        }
        let transport_mode = match encoded[1] {
            0 => transport::Mode::Tls,
            1 => transport::Mode::Quic,
            _ => return Err(ticket::Error::BadFormat),
        };
        let maximum = u32::from_be_bytes(
            encoded[3..7]
                .try_into()
                .map_err(|_| ticket::Error::BadFormat)?,
        );
        let max_early_data = match encoded[2] {
            0 if maximum == 0 => None,
            1 if Self::valid_allowance(transport_mode, maximum) => Some(maximum),
            _ => return Err(ticket::Error::BadFormat),
        };
        let mut transport_params_hash = [0u8; TRANSPORT_PARAMS_HASH_LEN];
        transport_params_hash.copy_from_slice(&encoded[7..ticket::LEGACY_CONTEXT_LEN]);
        let replay_domain = replay_domain
            .map(|()| {
                encoded[ticket::LEGACY_CONTEXT_LEN..ticket::CONTEXT_LEN]
                    .try_into()
                    .map_err(|_| ticket::Error::BadFormat)
            })
            .transpose()?;
        Ok(Self {
            transport_mode,
            max_early_data,
            transport_params_hash,
            replay_domain,
        })
    }

    pub(super) fn encoded_len(version: u8) -> Result<usize, ticket::Error> {
        match version {
            LEGACY_FORMAT_VERSION => Ok(ticket::LEGACY_CONTEXT_LEN),
            FORMAT_VERSION => Ok(ticket::CONTEXT_LEN),
            _ => Err(ticket::Error::BadFormat),
        }
    }

    fn valid_allowance(transport_mode: transport::Mode, maximum: u32) -> bool {
        maximum != 0
            && match transport_mode {
                transport::Mode::Tls => maximum != u32::MAX,
                transport::Mode::Quic => maximum == u32::MAX,
            }
    }
}
