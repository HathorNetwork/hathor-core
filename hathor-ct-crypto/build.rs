fn main() {
    #[cfg(feature = "napi")]
    napi_build::setup();

    // UniFFI uses proc-macros, no scaffolding generation needed
}
