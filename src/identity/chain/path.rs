use crate::identity::cert;
use crate::identity::chain;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureProof {
    NeedsVerification,
    Verified,
}

pub(super) struct Path {
    indices: arrayvec::ArrayVec<usize, { chain::MAX_LEN }>,
    /// One proof for each child→issuer link in `indices`.
    links: arrayvec::ArrayVec<SignatureProof, { chain::MAX_LEN }>,
}

impl Path {
    /// Leaf→up ordering by issuer/subject linkage (RFC 8446 §4.4.2 allows
    /// shuffled chains). A signature check breaks ties only when several
    /// candidates share the issuer DN (cross-signing).
    pub(super) fn build(chain: &[cert::Cert<'_>]) -> Self {
        let mut used = [false; chain::MAX_LEN];
        let mut indices = arrayvec::ArrayVec::new();
        let mut links = arrayvec::ArrayVec::new();
        let mut current_index = 0;
        used[0] = true;
        indices.push(0);
        loop {
            let current = &chain[current_index];
            let mut candidates = arrayvec::ArrayVec::<usize, { chain::MAX_LEN }>::new();
            for (index, candidate) in chain.iter().enumerate() {
                if used[index] || candidate.tbs.subject_der != current.tbs.issuer_der {
                    continue;
                }
                candidates.push(index);
            }
            let (chosen, proof) = match candidates.as_slice() {
                [] => break,
                &[index] => (index, SignatureProof::NeedsVerification),
                candidates => match candidates
                    .iter()
                    .copied()
                    .find(|&index| current.verify_signature(&chain[index].tbs.spki).is_ok())
                {
                    Some(index) => (index, SignatureProof::Verified),
                    None => (candidates[0], SignatureProof::NeedsVerification),
                },
            };
            used[chosen] = true;
            indices.push(chosen);
            links.push(proof);
            current_index = chosen;
        }
        Self { indices, links }
    }

    pub(super) fn indices(&self) -> &[usize] {
        &self.indices
    }

    pub(super) fn len(&self) -> usize {
        self.indices.len()
    }

    pub(super) fn requires_signature_verification(&self, position: usize) -> bool {
        self.links.get(position) != Some(&SignatureProof::Verified)
    }
}
