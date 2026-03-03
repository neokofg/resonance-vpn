fn main() {
    prost_build::compile_protos(&["../../proto/resonance.proto"], &["../../proto/"]).unwrap();
}
