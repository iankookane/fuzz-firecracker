#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::Arbitrary;
use utils::tempfile::TempFile;
use rate_limiter::{RateLimiter, TokenType};
use vm_memory::{Bytes, GuestMemoryMmap, GuestAddress};
use devices::virtio::{ActivateResult, Queue, VirtioDevice, TYPE_BLOCK, VIRTIO_MMIO_INT_VRING, Vsock};
const VIRTQ_DESC_F_NEXT: u16 = 0x1;
const VIRTQ_DESC_F_WRITE: u16 = 0x2;
const RXQ_INDEX: usize = 0;
const TXQ_INDEX: usize = 1;
const EVQ_INDEX: usize = 2;
use devices::virtio::queue::tests::VirtQueue as GuestQ;
use devices::virtio::vsock::csm::defs as csm_defs;
use devices::virtio::vsock::defs::uapi;
use devices::virtio::vsock::packet::{VsockPacket, VSOCK_PKT_HDR_SIZE};
use devices::virtio::vsock::unix::{Result};
use devices::virtio::vsock::unix::muxer::{VsockMuxer, EpollListener, ConnMapKey};
use devices::virtio::vsock::unix::muxer::tests::{MuxerTestContext};
use devices::virtio::vsock::{Result as VsockResult, VsockBackend, VsockChannel, VsockEpollListener, VsockError};
use polly::epoll::{EpollEvent, EventSet};
use polly::event_manager::{EventManager, Subscriber};
use logger::{Metric, METRICS};
use std::os::unix::io::{AsRawFd, RawFd};
extern crate libc;
use utils::eventfd::EventFd;
use std::io::{Read, Write};
use std::ops::Drop;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

fuzz_target!(|fuzzer_data: &[u8]| {
    const LOCAL_PORT: u32 = 1026;
    const PEER_PORT: u32 = 1025;
    const LOCAL_CID: u64 = 2;
    const PEER_CID: u64 = 3;

    // creates a real muxer (ctx) with a VsockTestContext (vsock/mod.rs)
    // which creates a 3 queues for guest virtio vsock and create a
    // creates a device (vsock<TestBackend>) which has virtual queues as well.
    // Testbackend seems to still use the send and recvpacket of the real code. (while the mock wants dont execute)
    // Both are used to create the event handler context,
    // which is used to make mutex.pkt. Which is the same as pkt
    // except it grabs the queue (created on line 2 comment)
    // from the vsock(device) with testbackend.
    // 
    let mut ctx = MuxerTestContext::new("peer_connection2");

     // Test peer connection refused.
     ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST);
     ctx.send();
     ctx.recv();
     assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RST);
     assert_eq!(ctx.pkt.len(), 0);
     assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
     assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
     assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
     assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

     // Test peer connection accepted.
     let mut listener = ctx.create_local_listener(LOCAL_PORT);
     ctx.init_pkt(LOCAL_PORT, PEER_PORT, uapi::VSOCK_OP_REQUEST);
     ctx.send();
     assert_eq!(ctx.muxer.conn_map.len(), 1);
     let mut stream = listener.accept();
     ctx.recv();
     assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RESPONSE);
     assert_eq!(ctx.pkt.len(), 0);
     assert_eq!(ctx.pkt.src_cid(), uapi::VSOCK_HOST_CID);
     assert_eq!(ctx.pkt.dst_cid(), PEER_CID);
     assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
     assert_eq!(ctx.pkt.dst_port(), PEER_PORT);
     let key = ConnMapKey {
         local_port: LOCAL_PORT,
         peer_port: PEER_PORT,
     };
     assert!(ctx.muxer.conn_map.contains_key(&key));

     // Test guest -> host data flow.
     let data = fuzzer_data;
     ctx.init_data_pkt(LOCAL_PORT, PEER_PORT, &data);
     ctx.send();
     let mut buf = vec![0; data.len()];
     stream.read_exact(buf.as_mut_slice()).unwrap();
     assert_eq!(buf.as_slice(), data);
    //  println!("{:?}", buf.as_slice());

     // Test host -> guest data flow.
     let data = [5u8, 6, 7, 8];
     stream.write_all(&data).unwrap();

     // When data is available on the local stream, an EPOLLIN event would normally be delivered
     // to the muxer's nested epoll FD. For testing only, we can fake that event notification
     // here.
     ctx.notify_muxer();
     // After being notified, the muxer should've figured out that RX data was available for one
     // of its connections, so it should now be reporting that it can fill in an RX packet.
     assert!(ctx.muxer.has_pending_rx());
     ctx.recv();
     assert_eq!(ctx.pkt.op(), uapi::VSOCK_OP_RW);
     assert_eq!(ctx.pkt.buf().unwrap()[..data.len()], data);
     assert_eq!(ctx.pkt.src_port(), LOCAL_PORT);
     assert_eq!(ctx.pkt.dst_port(), PEER_PORT);

     assert!(!ctx.muxer.has_pending_rx());
    // fuzzed code goes here
    //let _ = devices::virtio::block::build_config_space(data);
    // println!("{:?}", test);
});