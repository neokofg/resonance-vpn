pub mod crypto;
pub mod frame;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/resonance.rs"));
}
