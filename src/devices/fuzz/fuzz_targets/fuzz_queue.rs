#![no_main]
use libfuzzer_sys::fuzz_target;
// use libfuzzer_sys::arbitrary::Arbitrary;
use utils::tempfile::TempFile;
use rate_limiter::{RateLimiter, TokenType};
use vm_memory::{Bytes, GuestMemoryMmap, GuestMemory, GuestAddress};
use devices::virtio::block::{Block, request::*,
    Error, CONFIG_SPACE_SIZE, QUEUE_SIZES, SECTOR_SHIFT, SECTOR_SIZE};
use devices::virtio::{ActivateResult, Queue, VirtioDevice, TYPE_BLOCK, VIRTIO_MMIO_INT_VRING};
use devices::virtio::queue::{DescriptorChain};
use polly::epoll::{EpollEvent, EventSet};
use polly::event_manager::{EventManager, Subscriber};
use logger::{Metric, METRICS};
use std::os::unix::io::AsRawFd;
use bufrng::BufRng;
use rand::prelude::*;
use std::mem::size_of;

const MAX_QUEUE_SIZE: u16 = 256;
const MEM_SIZE: u64 = 1024 * 1024;

/// A virtio descriptor constraints with C representive.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct virtq_desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, packed)]
struct virtq_avail {
    flags: u16,
    idx: u16,
    ring: [u16; MAX_QUEUE_SIZE as usize],
    used_event: u16,
}

#[repr(C, packed)]
struct virtq_used {
    flags: u16,
    idx: u16,
    ring: [virtq_used_elem; MAX_QUEUE_SIZE as usize],
    avail_event: u16,
}

#[repr(C, packed)]
struct virtq_used_elem {
    id: u32,
    len: u32,
}

thread_local! {
    static GUEST_MEM: GuestMemoryMmap = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap();
}

fuzz_target!(|data: &[u8]| {
    let mut q = Queue::new(MAX_QUEUE_SIZE);
    let mut rng = BufRng::new(data);
    q.size = rng.gen::<u16>();
    q.ready = true;

    let max_table_size = MAX_QUEUE_SIZE as u64 * size_of::<virtq_desc>() as u64;
    q.desc_table = GuestAddress(rng.gen_range(0, MEM_SIZE - max_table_size));
    q.avail_ring = GuestAddress(rng.gen_range(0, MEM_SIZE - size_of::<virtq_avail>() as u64));
    q.used_ring = GuestAddress(rng.gen_range(0, MEM_SIZE - size_of::<virtq_used>() as u64));

    GUEST_MEM.with(|mem| {
        if !q.is_valid(mem) {
            return;
        }
        // First zero out all of the memory.
        let zeros: [u8; MEM_SIZE as usize] = [0; MEM_SIZE as usize];
        let vs = mem.write_slice(&zeros, GuestAddress(0)).unwrap();
        
        // Fill in the descriptor table.
        let queue_size = q.size as usize;
        let mut buf = vec![0u8; queue_size * size_of::<virtq_desc>()];
        rng.fill_bytes(&mut buf[..]);
        mem.write_slice(&buf[..], q.desc_table).unwrap();

        // Fill in the available ring. See the definition of virtq_avail above for the source of
        // these numbers.
        let avail_size = 4 + (queue_size * 2) + 2;
        buf.resize(avail_size, 0);
        rng.fill_bytes(&mut buf[..]);
        mem.write_slice(&buf[..], q.avail_ring).unwrap();


        // Fill in the used ring. See the definition of virtq_used above for the source of
        // these numbers.
        let used_size = 4 + (queue_size * size_of::<virtq_used_elem>()) + 2;
        buf.resize(used_size, 0);
        rng.fill_bytes(&mut buf[..]);
        mem.write_slice(&buf[..], q.used_ring).unwrap();

        while let Some(avail_desc) = q.pop(mem) {
            let idx = avail_desc.index;

            let mut total = 0;
            let mut temp = avail_desc;
            while (temp.has_next()) {
                temp = temp.next_descriptor().unwrap();
                if (temp.is_write_only()) {
                    total = total+1;
                }
            }
            q.add_used(mem, idx, total);
        }
    });

});
