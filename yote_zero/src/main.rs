use anyhow::Result;
use std::ffi::{c_char, c_int, c_void};

const ZT_RING_BYTES: i32 = 65536;
const ZT_MAGIC: u64 = 0x594F5445; // "YOTE"

#[repr(C)]
struct ZtHandle {
    fd: c_int,
    vbase: *mut c_void,
    ring: *mut c_void,
    ring_bytes: usize,
}

#[repr(C)]
struct ZeroPolicyFrame {
    record_hdr: u64,
    magic_opcode: u64,
    entity_id: u64,
    payload_len: u32,
    capability_bit: u32,
    payload: [u8; 32],
}

extern "C" {
    fn zt_alloc(ring_bytes: c_int) -> *mut ZtHandle;
    fn zt_free(h: *mut ZtHandle);
    fn zt_push(
        h: *mut ZtHandle,
        payload: *const u8,
        payload_len: c_int,
        entity_id: u64,
        capability_bit: u32,
    ) -> c_int;
    fn zt_pop(
        h: *mut ZtHandle,
        out: *mut u8,
        out_cap: c_int,
        entity_id: *mut u64,
        capability_bit: *mut u32,
    ) -> c_int;
    fn zt_get_fd(h: *const ZtHandle) -> c_int;
    fn zt_ring_bytes(h: *const ZtHandle) -> usize;
    fn zt_verify(f: *const ZeroPolicyFrame, allowed_bitmap: u64) -> bool;
}

pub struct ZeroTransport {
    handle: *mut ZtHandle,
}

impl ZeroTransport {
    pub fn new(ring_bytes: c_int) -> Result<Self> {
        let handle = unsafe { zt_alloc(ring_bytes) };
        if handle.is_null() {
            anyhow::bail!("zt_alloc returned null");
        }
        Ok(ZeroTransport { handle })
    }

    pub fn push(&self, payload: &[u8], entity_id: u64, capability_bit: u32) -> Result<usize> {
        if payload.len() > 32 {
            anyhow::bail!("payload too large (max 32 bytes)");
        }
        let n = unsafe {
            zt_push(
                self.handle,
                payload.as_ptr(),
                payload.len() as c_int,
                entity_id,
                capability_bit,
            )
        };
        if n < 0 {
            anyhow::bail!("push failed with errno {}", -n);
        }
        Ok(n as usize)
    }

    pub fn pop(&self, out: &mut [u8]) -> Result<(usize, u64, u32)> {
        let mut entity_id: u64 = 0;
        let mut capability_bit: u32 = 0;
        let n = unsafe {
            zt_pop(
                self.handle,
                out.as_mut_ptr(),
                out.len() as c_int,
                &mut entity_id,
                &mut capability_bit,
            )
        };
        if n < 0 {
            anyhow::bail!("pop failed with errno {}", -n);
        }
        Ok((n as usize, entity_id, capability_bit))
    }

    pub fn fd(&self) -> c_int {
        unsafe { zt_get_fd(self.handle) }
    }

    pub fn ring_bytes(&self) -> usize {
        unsafe { zt_ring_bytes(self.handle) }
    }

    pub fn verify_frame(entity_id: u64, capability_bit: u32, allowed_bitmap: u64) -> bool {
        let frame = ZeroPolicyFrame {
            record_hdr: 0,
            magic_opcode: (ZT_MAGIC << 32),
            entity_id,
            payload_len: 0,
            capability_bit,
            payload: [0; 32],
        };
        unsafe { zt_verify(&frame as *const _, allowed_bitmap) }
    }
}

impl Drop for ZeroTransport {
    fn drop(&mut self) {
        unsafe { zt_free(self.handle) };
    }
}

fn main() {
    println!("Testing yote-zero...");
    let ring_bytes = ZT_RING_BYTES;

    let zt = ZeroTransport::new(ring_bytes).expect("failed to allocate ring");
    println!("yote-zero: ring allocated, fd={}, bytes={}", zt.fd(), zt.ring_bytes());

    // Test push/pop
    let payload = b"YOTE_TEST_3988730";
    let n = zt.push(payload, 3988730, 0).expect("push failed");
    println!("pushed {} bytes", n);

    let mut out = [0u8; 32];
    let (n, entity_id, cap) = zt.pop(&mut out).expect("pop failed");
    let msg = String::from_utf8_lossy(&out[..n]);
    println!("popped: {} (entity={}, cap={})", msg, entity_id, cap);

    // Test verify
    let ok = ZeroTransport::verify_frame(8932201107, 42, 1u64 << 42);
    println!("verify bot 8932201107 cap 42: {}", ok);

    println!("yote-zero: OK");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zt_alloc_and_free() {
        let h = ZeroTransport::new(ZT_RING_BYTES).expect("alloc should succeed");
        assert!(!h.handle.is_null());
    }

    #[test]
    fn test_zt_push_pop_roundtrip() {
        let h = ZeroTransport::new(ZT_RING_BYTES).expect("alloc should succeed");
        let payload = b"hello yote zero transport";
        let n = h.push(payload, 8932201107, 42).expect("push should succeed");
        assert_eq!(n, payload.len());

        let mut out = [0u8; 32];
        let (n, eid, cap) = h.pop(&mut out).expect("pop should succeed");
        assert_eq!(n, payload.len());
        assert_eq!(&out[..payload.len()], payload);
        assert_eq!(eid, 8932201107);
        assert_eq!(cap, 42);
    }

    #[test]
    fn test_zt_multiple_push_pop() {
        let h = ZeroTransport::new(ZT_RING_BYTES).expect("alloc should succeed");
        for i in 0..100 {
            let payload = format!("msg{}", i).into_bytes();
            h.push(&payload, i as u64, i as u32).expect("push should succeed");
        }
        for i in 0..100 {
            let mut out = [0u8; 32];
            let (n, eid, cap) = h.pop(&mut out).expect("pop should succeed");
            let expected = format!("msg{}", i).into_bytes();
            assert_eq!(n, expected.len());
            assert_eq!(&out[..expected.len()], expected);
            assert_eq!(eid, i as u64);
            assert_eq!(cap, i as u32);
        }
    }

    #[test]
    fn test_zt_verify() {
        // Test magic check passes (frame with magic, payload_len=0)
        assert!(ZeroTransport::verify_frame(0, 0, 1));
        
        // Test capability bit check
        assert!(ZeroTransport::verify_frame(0, 5, 1u64 << 5));
        assert!(!ZeroTransport::verify_frame(0, 5, 0));
    }
}
