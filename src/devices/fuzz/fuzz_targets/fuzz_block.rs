#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::Arbitrary;
use utils::tempfile::TempFile;
use rate_limiter::{RateLimiter, TokenType};
use vm_memory::{Bytes, GuestMemoryMmap, GuestAddress};
use devices::virtio::block::{Block, request::*,
    Error, CONFIG_SPACE_SIZE, QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE};
use devices::virtio::{ActivateResult, Queue, VirtioDevice, TYPE_BLOCK, VIRTIO_MMIO_INT_VRING};
use devices::virtio::queue::tests::VirtQueue;
use polly::epoll::{EpollEvent, EventSet};
use polly::event_manager::{EventManager, Subscriber};
use logger::{Metric, METRICS};
use utils::eventfd::EventFd;
const VIRTQ_DESC_F_NEXT: u16 = 0x1;
const VIRTQ_DESC_F_WRITE: u16 = 0x2;
const VIRTIO_BLK_S_OK: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

fn create_block() -> Block {
    let f = TempFile::new().unwrap();
    let block_file = f.into_file();
    block_file.set_len(0x1000).unwrap();
    let rate_limiter = RateLimiter::new(0, None, 0, 100_000, None, 10).unwrap();

    let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
    Block::new(mem, block_file, true, rate_limiter).unwrap()
}

fn initialize_virtqueue(vq: &VirtQueue) {
    let request_type_desc: usize = 0;
    let data_desc: usize = 1;
    let status_desc: usize = 2;

    let request_addr: u64 = 0x1000;
    let data_addr: u64 = 0x2000;
    let status_addr: u64 = 0x3000;
    let len = 0x1000;

    // Set the request type descriptor.
    vq.avail.ring[request_type_desc].set(request_type_desc as u16);
    vq.dtable[request_type_desc].set(request_addr, len, VIRTQ_DESC_F_NEXT, data_desc as u16);

    // Set the data descriptor.
    vq.avail.ring[data_desc].set(data_desc as u16);
    vq.dtable[data_desc].set(
        data_addr,
        len,
        VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE,
        status_desc as u16,
    );

    // Set the status descriptor.
    vq.avail.ring[status_desc].set(status_desc as u16);
    vq.dtable[status_desc].set(
        status_addr,
        len,
        VIRTQ_DESC_F_WRITE,
        (status_desc + 1) as u16,
    );

    // Mark the next available descriptor.
    vq.avail.idx.set(1);
}

fn invoke_handler_for_queue_event(b: &mut Block) {
    // Trigger the queue event.
    b.queue_evt.write(1).unwrap();
    // Handle event.
    b.process(
        &EpollEvent::new(EventSet::IN, b.queue_evt.as_raw_fd() as u64),
        &mut EventManager::new().unwrap(),
    );
    // Validate the queue operation finished successfully.
    assert_eq!(b.interrupt_evt.read().unwrap(), 1);
}

fuzz_target!(|data: u64| {
    /// Will read $metric, run the code in $block, then assert metric has increased by $delta.
    macro_rules! check_metric_after_block {
        ($metric:expr, $delta:expr, $block:expr) => {{
            let before = $metric.count();
            let _ = $block;
            assert_eq!($metric.count(), before + $delta, "unexpected metric value");
        }};
    }


    // TODO: make necessary attributes public https://github.com/rust-fuzz/cargo-fuzz/issues/156
    // Note that crosvm has block.activate which allows you to pass queues and events so this wouldn't be needed
    // Later can try attaching a block device see src/vmm/builder.rs
    let mut block = create_block();
    let mem = block.mem.clone();
    let vq = VirtQueue::new(GuestAddress(0), &mem, 16);
    block.queues[0] = vq.create_queue();
    block.set_device_activated(true);
    initialize_virtqueue(&vq);

    let request_type_addr = GuestAddress(vq.dtable[0].addr.get());
    let data_addr = GuestAddress(vq.dtable[1].addr.get());
    let status_addr = GuestAddress(vq.dtable[2].addr.get());

    block.set_device_activated(true);


    mem.write_obj::<u32>(VIRTIO_BLK_T_OUT, request_type_addr)
        .unwrap();
    // Make data read only, 8 bytes in len, and set the actual value to be written.
    vq.dtable[1].flags.set(VIRTQ_DESC_F_NEXT);
    vq.dtable[1].len.set(8);
    mem.write_obj::<u64>(123_456_789, data_addr).unwrap();

    check_metric_after_block!(
        &METRICS.block.write_count,
        1,
        invoke_handler_for_queue_event(&mut block)
    );

    assert_eq!(vq.used.idx.get(), 1);
    assert_eq!(vq.used.ring[0].get().id, 0);
    assert_eq!(vq.used.ring[0].get().len, 0);
    assert_eq!(mem.read_obj::<u32>(status_addr).unwrap(), VIRTIO_BLK_S_OK);


    // println!("{:?}", "test");
    let _ = devices::virtio::block::build_config_space(data);
});
