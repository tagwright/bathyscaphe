// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud
//! The `DNS_QUERIES` `RingBuf` consumer (build chunk #10): the same
//! plumbing-only shape as `probe::dns::DnsCaptureConsumer` (a dedicated
//! `poll(2)`-driven OS thread, the identical shutdown-flag-and-join
//! lifecycle), decoding `bathyscaphe_common::DnsQueryCapture` records
//! instead of `DnsCapture`s. Feeding the decoded record into the
//! query/response correlation table is `crate::dns::pending`'s job, wired
//! in by the daemon -- this module's only responsibility is getting a
//! well-formed record off the ring and handing it to a callback.

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use aya::maps::{MapData, RingBuf};
use bathyscaphe_common::DnsQueryCapture;

/// Callback invoked once per decoded DNS query capture, on the consumer
/// thread. Must not block for long -- identical rationale to
/// `probe::dns::DnsCallback`'s doc.
pub type DnsQueryCallback = Box<dyn FnMut(DnsQueryCapture) + Send + 'static>;

/// Matches `probe::events::POLL_TIMEOUT_MS` / `probe::dns`'s consumer
/// exactly -- same rationale, same bound on shutdown latency.
const POLL_TIMEOUT_MS: i32 = 250;

/// Owns the consumer thread. Same drop-detaches-rather-than-panics
/// contract as `probe::dns::DnsCaptureConsumer`.
pub struct DnsQueryCaptureConsumer {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl DnsQueryCaptureConsumer {
    /// Spawns the consumer thread, taking ownership of `ring` (typically
    /// via [`crate::probe::Probe::take_dns_queries`]) and `callback`.
    pub fn spawn(ring: RingBuf<MapData>, mut callback: DnsQueryCallback) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_thread = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            let mut ring = ring;
            let fd = ring.as_raw_fd();
            loop {
                while let Some(item) = ring.next() {
                    if let Some(capture) = decode_capture(&item) {
                        callback(capture);
                    }
                }
                if shutdown_thread.load(Ordering::Relaxed) {
                    break;
                }
                let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                // SAFETY: identical to `probe::dns::DnsCaptureConsumer`'s use
                // of this same call.
                unsafe {
                    libc::poll(&mut pfd, 1, POLL_TIMEOUT_MS);
                }
            }
        });
        Self { shutdown, handle: Some(handle) }
    }

    /// Signals the consumer thread to stop after draining whatever is
    /// currently in the ring, and joins it.
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Decodes one ring buffer record as a [`DnsQueryCapture`]. Returns `None`
/// (and logs to stderr) on a size mismatch -- identical defensive shape to
/// `probe::dns::decode_capture`.
fn decode_capture(item: &[u8]) -> Option<DnsQueryCapture> {
    if item.len() != DnsQueryCapture::WIRE_SIZE {
        eprintln!("bathyscaphe: dns query ringbuf record has unexpected size {} (expected {}); dropping it", item.len(), DnsQueryCapture::WIRE_SIZE);
        return None;
    }
    // SAFETY: `DnsQueryCapture` is `#[repr(C)]` and `aya::Pod`, the length
    // was just checked, and `read_unaligned` makes no alignment assumption
    // about `item` -- identical reasoning to `probe::dns::decode_capture`.
    let capture = unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<DnsQueryCapture>()) };
    Some(capture)
}

/// The privileged empirical investigation the build brief mandates: prove
/// on THIS host, precisely, whether (a) the egress query snoop fires in
/// the CONTAINER's own cgroup (the whole premise of the query/response
/// correlation fix), and (b) correlation actually attributes a
/// Docker-embedded-DNS (`127.0.0.11`) answer to that container, overriding
/// the ingress response hook's own (per chunk #9, likely wrong)
/// attribution. `#[ignore]`d for the same reason every other `live_smoke`
/// module in this crate is -- needs root, a real cgroup v2 host, a
/// writable bpffs, and a reachable Docker socket. See `docs/TESTING.md`
/// for what this proved when it was actually run.
#[cfg(test)]
mod live_smoke {
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use bathyscaphe_common::{DnsCapture, DnsQueryCapture};

    use crate::attribution::cgroup::{DEFAULT_CGROUP_ROOT, classify_trailing_segment};
    use crate::dns::PendingQueryTable;
    use crate::probe::Probe;

    const TEST_CONTAINER_NAME: &str = "bathyscaphe-itest-fqdn-smoke";
    const TEST_NETWORK_NAME: &str = "bathyscaphe-itest-fqdn-net";
    const DOCKER_SOCKET: &str = "/var/run/docker.sock";
    const API_VERSION: &str = "v1.44";
    const BPFFS_ROOT: &str = "/sys/fs/bpf/bathyscaphe-fqdn-smoke-test";

    fn running_as_root() -> bool {
        // SAFETY: geteuid() takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    fn docker_socket_reachable() -> bool {
        UnixStream::connect(DOCKER_SOCKET).is_ok()
    }

    /// Identical tiny HTTP/1.0-over-unix-socket client to
    /// `probe::dns::live_smoke`'s -- see that module's doc for why this
    /// test talks to the Docker API directly rather than through bollard.
    fn docker_api(method: &str, path: &str, body: &str) -> Result<(u16, String), std::io::Error> {
        let mut stream = UnixStream::connect(DOCKER_SOCKET)?;
        let request = if body.is_empty() {
            format!("{method} {path} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        } else {
            format!("{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
        };
        std::io::Write::write_all(&mut stream, request.as_bytes())?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;

        let mut lines = response.splitn(2, "\r\n");
        let status_line = lines.next().unwrap_or_default();
        let status: u16 = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let rest = lines.next().unwrap_or_default();
        let json_body = rest.rsplit_once("\r\n\r\n").map(|(_, body)| body).unwrap_or(rest);
        Ok((status, json_body.trim().to_string()))
    }

    /// A user-defined bridge network -- REQUIRED (not incidental) for this
    /// test: only user-defined networks get Docker's embedded per-container
    /// DNS resolver at `127.0.0.11:53`, which is precisely the delivery
    /// path chunk #9 found misattributes to `docker.service`'s cgroup and
    /// this chunk's correlation exists to fix.
    fn ensure_test_network() -> Result<(), String> {
        let create_body = format!(r#"{{"Name":"{TEST_NETWORK_NAME}","Driver":"bridge"}}"#);
        let (status, body) = docker_api("POST", &format!("/{API_VERSION}/networks/create"), &create_body).map_err(|e| e.to_string())?;
        if status != 201 && status != 409 {
            return Err(format!("network create failed: HTTP {status}: {body}"));
        }
        Ok(())
    }

    fn remove_test_network() {
        let _ = docker_api("DELETE", &format!("/{API_VERSION}/networks/{TEST_NETWORK_NAME}"), "");
    }

    fn create_and_start_test_container() -> Result<String, String> {
        let create_body = format!(r#"{{"Image":"alpine:latest","Cmd":["sh","-c","sleep 1 && nslookup example.com; sleep 4"],"Tty":false,"HostConfig":{{"NetworkMode":"{TEST_NETWORK_NAME}"}}}}"#);
        let (status, body) = docker_api("POST", &format!("/{API_VERSION}/containers/create?name={TEST_CONTAINER_NAME}"), &create_body).map_err(|e| e.to_string())?;
        if status != 201 {
            return Err(format!("container create failed: HTTP {status}: {body}"));
        }
        let parsed: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("create response was not JSON ({e}): {body}"))?;
        let container_id = parsed.get("Id").and_then(|v| v.as_str()).ok_or_else(|| format!("create response had no Id: {body}"))?.to_string();

        let (status, body) = docker_api("POST", &format!("/{API_VERSION}/containers/{container_id}/start"), "").map_err(|e| e.to_string())?;
        if status != 204 {
            return Err(format!("container start failed: HTTP {status}: {body}"));
        }
        Ok(container_id)
    }

    fn remove_test_container(container_id: &str) {
        let _ = docker_api("DELETE", &format!("/{API_VERSION}/containers/{container_id}?force=true"), "");
    }

    fn find_cgroup_path_for(root: &Path, container_id: &str) -> Option<PathBuf> {
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else { continue };
                if !file_type.is_dir() {
                    continue;
                }
                let path = entry.path();
                if let Some(found) = classify_trailing_segment(&path) {
                    if found.container_id == container_id {
                        return Some(path);
                    }
                }
                stack.push(path);
            }
        }
        None
    }

    enum FqdnSmokeOutcome {
        /// The full claim, end to end: the query fired in the container's
        /// own cgroup, the response's OWN cgroup differed (the chunk #9
        /// misattribution reproduced), and correlation recovered the
        /// correct (container's) cgroup id for the response.
        FullCorrelationProof { query_cgroup_matched_container: bool, response_own_cgroup_matched_container: bool, correlated_cgroup_matched_container: bool },
        /// The query snoop captured nothing at all within the deadline --
        /// a real defect to report, not tolerated.
        NoQueryCaptured,
        /// The response snoop captured nothing at all within the deadline
        /// -- also a real defect (chunk #9 already proved this path
        /// works on this host, so a regression here is unexpected).
        NoResponseCaptured,
    }

    #[test]
    #[ignore = "requires root, --privileged, a real cgroup2 host, a writable bpffs, and a reachable Docker socket -- see docs/TESTING.md"]
    fn query_response_correlation_recovers_the_correct_container_cgroup() {
        if !running_as_root() {
            eprintln!("fqdn live_smoke: skipping, not running as root");
            return;
        }
        if !docker_socket_reachable() {
            eprintln!("fqdn live_smoke: skipping, {DOCKER_SOCKET} is not reachable in this environment");
            return;
        }

        remove_test_container(TEST_CONTAINER_NAME);
        if let Err(error) = ensure_test_network() {
            panic!("failed to ensure the throwaway test network exists: {error}");
        }
        let bpffs_root = PathBuf::from(BPFFS_ROOT);
        let _ = Probe::unpin_all_at(&bpffs_root);

        let mut probe = Probe::load_or_reopen(crate::EBPF_OBJECT, bpffs_root.clone())
            .expect("fresh load_or_reopen should load, pin, and reopen cleanly for all SEVEN programs including dns_query_snoop -- a verifier rejection surfaces here");

        let container_id = match create_and_start_test_container() {
            Ok(id) => id,
            Err(error) => {
                let _ = probe.unpin_all();
                remove_test_network();
                panic!("failed to create the throwaway test container: {error}");
            }
        };

        let outcome: Result<FqdnSmokeOutcome, String> = (|| {
            let deadline = Instant::now() + Duration::from_secs(10);
            let cgroup_path = loop {
                if let Some(path) = find_cgroup_path_for(Path::new(DEFAULT_CGROUP_ROOT), &container_id) {
                    break path;
                }
                if Instant::now() > deadline {
                    return Err("timed out waiting for the container's cgroup directory to appear".to_string());
                }
                std::thread::sleep(Duration::from_millis(50));
            };

            let container_cgroup_id =
                probe.attach_container(&cgroup_path).map_err(|e| format!("attach_container failed (this is where a verifier rejection of dns_query_snoop or dns_snoop would surface): {e:#}"))?;

            let mut query_ring = probe.take_dns_queries().ok_or("DNS query ring buffer already taken")?;
            let mut answer_ring = probe.take_dns_events().ok_or("DNS answer ring buffer already taken")?;

            // Drain BOTH rings concurrently (a single poll loop) for up to
            // 12s, collecting every query and every answer capture seen --
            // the container's `nslookup example.com` fires one query and
            // (typically) one A + one AAAA response in short order.
            let mut queries: Vec<DnsQueryCapture> = Vec::new();
            let mut answers: Vec<DnsCapture> = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(12);
            while Instant::now() < deadline {
                while let Some(item) = query_ring.next() {
                    if item.len() != DnsQueryCapture::WIRE_SIZE {
                        continue;
                    }
                    // SAFETY: length just checked; matches `decode_capture`'s
                    // own reasoning in this module.
                    queries.push(unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<DnsQueryCapture>()) });
                }
                while let Some(item) = answer_ring.next() {
                    if item.len() != DnsCapture::WIRE_SIZE {
                        continue;
                    }
                    answers.push(unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<DnsCapture>()) });
                }
                if !queries.is_empty() && !answers.is_empty() {
                    // Give a brief extra window for a second answer
                    // (A + AAAA) to arrive before declaring done.
                    std::thread::sleep(Duration::from_millis(300));
                    while let Some(item) = answer_ring.next() {
                        if item.len() == DnsCapture::WIRE_SIZE {
                            answers.push(unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<DnsCapture>()) });
                        }
                    }
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            if queries.is_empty() {
                return Ok(FqdnSmokeOutcome::NoQueryCaptured);
            }
            if answers.is_empty() {
                return Ok(FqdnSmokeOutcome::NoResponseCaptured);
            }

            // Claim (a): the egress query snoop fires in the CONTAINER's
            // own cgroup, always -- check every captured query.
            let query_cgroup_matched_container = queries.iter().all(|q| q.cgroup_id == container_cgroup_id);
            eprintln!(
                "fqdn live_smoke: {} quer{} captured; cgroup_id{} {:016x} (container's real cgroup is {container_cgroup_id:016x}) -- query_cgroup_matched_container={query_cgroup_matched_container}",
                queries.len(),
                if queries.len() == 1 { "y" } else { "ies" },
                if queries.len() == 1 { "" } else { "s" },
                queries[0].cgroup_id
            );

            // Claim (b): correlate every captured answer and compare
            // against its OWN (response-hook) cgroup attribution.
            let mut pending = PendingQueryTable::new();
            for q in &queries {
                pending.record_query(q.txid, q.src_port, q.cgroup_id, q.ktime_ns);
            }

            let mut response_own_cgroup_matched_container = true;
            let mut correlated_cgroup_matched_container = true;
            for a in &answers {
                let txid_bytes: [u8; 2] = match a.captured().get(0..2) {
                    Some(b) => [b[0], b[1]],
                    None => continue,
                };
                let txid = u16::from_be_bytes(txid_bytes);
                let own_matched = a.cgroup_id == container_cgroup_id;
                let correlated = pending.correlate(txid, a.dst_port, a.ktime_ns);
                let correlated_matched = correlated == crate::dns::Correlation::Resolved(container_cgroup_id);
                eprintln!(
                    "fqdn live_smoke: answer txid={txid:04x} dst_port={} response's own cgroup_id={:016x} (matched container: {own_matched}) correlated cgroup_id={:?} (matched container: {correlated_matched})",
                    a.dst_port, a.cgroup_id, correlated
                );
                response_own_cgroup_matched_container &= own_matched;
                correlated_cgroup_matched_container &= correlated_matched;
            }

            Ok(FqdnSmokeOutcome::FullCorrelationProof { query_cgroup_matched_container, response_own_cgroup_matched_container, correlated_cgroup_matched_container })
        })();

        remove_test_container(&container_id);
        remove_test_network();
        let _ = probe.unpin_all();

        match outcome.expect("attach_container must succeed (verifier acceptance for all seven programs) and BOTH the query and answer snoops must capture SOMETHING; see docs/TESTING.md") {
            FqdnSmokeOutcome::FullCorrelationProof { query_cgroup_matched_container, response_own_cgroup_matched_container, correlated_cgroup_matched_container } => {
                assert!(
                    query_cgroup_matched_container,
                    "the egress query snoop MUST fire in the container's own cgroup -- this is the entire premise of the correlation fix, and a failure here is a real defect, not a tolerated confound"
                );
                assert!(correlated_cgroup_matched_container, "query/response correlation MUST recover the container's cgroup id for every captured answer");
                eprintln!(
                    "fqdn live_smoke: FULL PROOF -- egress query snoop correctly attributed to the container's own cgroup in every case; response's OWN cgroup attribution matched the container in {} case(s) (chunk #9's docker.service misattribution {}); correlation recovered the correct container cgroup in every case regardless",
                    if response_own_cgroup_matched_container { "every" } else { "zero" },
                    if response_own_cgroup_matched_container { "did NOT reproduce this run" } else { "reproduced exactly as chunk #9 documented" }
                );
            }
            FqdnSmokeOutcome::NoQueryCaptured => panic!("dns_query_snoop captured NOTHING at all within the deadline -- this DOES indicate a capture-logic problem, not a tolerable confound"),
            FqdnSmokeOutcome::NoResponseCaptured => {
                panic!("dns_snoop captured NOTHING at all within the deadline -- this DOES indicate a capture-logic problem (chunk #9 already proved this path works on this host)")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture_bytes(capture: &DnsQueryCapture) -> Vec<u8> {
        // SAFETY: `DnsQueryCapture` is `#[repr(C)]` and `Pod`; reading its
        // bytes for a test fixture is exactly what the kernel side does
        // when it writes one into the ring buffer.
        unsafe { std::slice::from_raw_parts((capture as *const DnsQueryCapture).cast::<u8>(), DnsQueryCapture::WIRE_SIZE).to_vec() }
    }

    #[test]
    fn decode_capture_round_trips_a_well_formed_record() {
        let capture = DnsQueryCapture::new(42, 0xABCD, 0x1234, 5353);
        let bytes = capture_bytes(&capture);

        let decoded = decode_capture(&bytes).expect("well-formed capture decodes");
        assert_eq!(decoded, capture);
    }

    #[test]
    fn decode_capture_rejects_a_short_buffer() {
        let short = vec![0u8; DnsQueryCapture::WIRE_SIZE - 1];
        assert!(decode_capture(&short).is_none());
    }

    #[test]
    fn decode_capture_rejects_an_oversized_buffer() {
        let long = vec![0u8; DnsQueryCapture::WIRE_SIZE + 1];
        assert!(decode_capture(&long).is_none());
    }
}
