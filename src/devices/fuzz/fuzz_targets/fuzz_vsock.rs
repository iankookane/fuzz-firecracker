#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::Arbitrary;

// #[derive(Arbitrary, Debug)]
// pub u64

extern crate devices;
fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    //let _ = devices::virtio::block::build_config_space(data);
    let test = u64::new(data);
    println!("{:?}", test);
});