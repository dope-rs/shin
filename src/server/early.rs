use arrayvec::ArrayVec;

use crate::connection::Error;
use crate::memory::bound::ThreadBound;
use crate::wire::record::CipherSuite;
use zeroize::Zeroize;

use super::EarlyDataGuard;

const MAX_TICKET_AGE_SKEW_MS: u64 = 10_000;
const MAX_EARLY_DATA_SIZE: u32 = 16_384;
pub(super) const TICKET_LIFETIME_SECS: u32 = 7_200;
const TICKET_LIFETIME_MS: u64 = TICKET_LIFETIME_SECS as u64 * 1_000;

pub(super) struct AcceptedPsk {
    pub(super) psk: [u8; 32],
    pub(super) age_add: u32,
    pub(super) issued_at_ms: u64,
    pub(super) suite: u16,
    pub(super) obfuscated_ticket_age: u32,
    pub(super) binder: [u8; 32],
    pub(super) alpn: ArrayVec<u8, 255>,
    pub(super) _thread: ThreadBound,
}

impl AcceptedPsk {
    pub(super) fn issued_at_is_resumable(issued_at_ms: u64, now_ms: u64) -> bool {
        issued_at_ms <= now_ms.saturating_add(MAX_TICKET_AGE_SKEW_MS)
            && now_ms.saturating_sub(issued_at_ms) <= TICKET_LIFETIME_MS
    }
}

impl Drop for AcceptedPsk {
    fn drop(&mut self) {
        self.psk.zeroize();
    }
}

pub(super) struct EarlyDataAdmission {
    enabled: bool,
    remaining: Option<u32>,
}

impl EarlyDataAdmission {
    pub(super) fn new() -> Self {
        Self {
            enabled: false,
            remaining: None,
        }
    }

    pub(super) fn admit<G: EarlyDataGuard>(
        &mut self,
        guard: &mut G,
        offered: bool,
        psk: Option<&AcceptedPsk>,
        selected_alpn: Option<&[u8]>,
        suite: Option<CipherSuite>,
        now_ms: u64,
    ) -> bool {
        let enabled = G::ACCEPTS_EARLY_DATA;
        self.remaining = None;
        self.enabled = enabled;
        if !enabled || !offered {
            return false;
        }
        let Some(psk) = psk else {
            return false;
        };
        let selected_alpn = selected_alpn.unwrap_or_default();
        if selected_alpn != psk.alpn.as_slice()
            || suite.map(CipherSuite::wire_id) != Some(psk.suite)
        {
            return false;
        }
        if now_ms < psk.issued_at_ms {
            return false;
        }
        let measured_age = now_ms - psk.issued_at_ms;
        let claimed_age = psk.obfuscated_ticket_age.wrapping_sub(psk.age_add) as u64;
        if measured_age > TICKET_LIFETIME_MS
            || measured_age.abs_diff(claimed_age) > MAX_TICKET_AGE_SKEW_MS
        {
            return false;
        }
        if !guard.register(&psk.binder) {
            return false;
        }
        self.remaining = Some(MAX_EARLY_DATA_SIZE);
        true
    }

    pub(super) fn advertised_size(&self) -> Option<u32> {
        self.enabled.then_some(MAX_EARLY_DATA_SIZE)
    }

    pub(super) fn open_size(&self) -> Option<u32> {
        self.remaining.map(|_| MAX_EARLY_DATA_SIZE)
    }

    pub(super) fn charge(&mut self, len: usize) -> Result<(), Error> {
        let Some(remaining) = self.remaining.as_mut() else {
            return Err(Error::EarlyDataLimitExceeded);
        };
        let Some(left) = u32::try_from(len)
            .ok()
            .and_then(|len| remaining.checked_sub(len))
        else {
            self.remaining = None;
            return Err(Error::EarlyDataLimitExceeded);
        };
        *remaining = left;
        Ok(())
    }

    pub(super) fn close(&mut self) {
        self.remaining = None;
    }
}
