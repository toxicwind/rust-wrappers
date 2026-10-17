fn main() {
    println!("cargo:rustc-link-search=native=/home/toxic/src");
    println!("cargo:rustc-link-lib=zero_transport");
    println!("cargo:rerun-if-changed=/home/toxic/src/libzero_transport.so");
}
