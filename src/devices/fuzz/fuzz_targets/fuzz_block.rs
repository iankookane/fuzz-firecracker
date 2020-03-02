#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::Arbitrary;

fuzz_target!(|data: u64| {
    // TODO: moved to different branch
    let _ = devices::virtio::block::build_config_space(data);
});
