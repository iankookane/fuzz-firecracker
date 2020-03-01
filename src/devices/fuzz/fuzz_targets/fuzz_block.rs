#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::Arbitrary;

fn create_block() -> Block {
    let f = TempFile::new().unwrap();
    let block_file = f.into_file();
    block_file.set_len(0x1000).unwrap();

    let rate_limiter = RateLimiter::new(0, None, 0, 100_000, None, 10).unwrap();

    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();

    Block::new(mem, block_file, true, rate_limiter).unwraper();
}

fuzz_target!(|data: u64| {
    let test_string = "hello";
    let test_block = create_block();
    println!("{:?}", test_block);
    println!("{:?}", test_string);
    let _ = devices::virtio::block::build_config_space(data);
});
