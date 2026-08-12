mod aes256_sha384;
mod alpn;
mod cert_type_negotiation;
mod cipher_suite;
mod client_conformance;
mod common;
mod downgrade;
mod early_data;
mod early_data_limit;
mod exporter;
mod finished_integrity;
mod handshake_e2e;
mod handshake_ecdsa;
mod handshake_ecdsa_p384;
mod handshake_reassembly;
mod handshake_resumption;
mod handshake_rsa;
mod handshake_x509;
mod hrr;
mod interop_rustls;
mod mlkem_kx;
mod mutual_auth;
mod p256_kx;
mod psk_ch_offer;
mod psk_hrr;
mod sha384_negotiation;
mod sni;
mod state_machine;
mod ticket_rotation;
mod zero_rtt;

use shin::wire::codec::{DecodeError, Reader};
use shin::wire::handshake::frame::{Frame, MessageRef};

fn decode_owned<'a>(reader: &mut Reader<'a>) -> Result<Frame, DecodeError> {
    MessageRef::decode_from(reader).map(MessageRef::into_owned)
}
