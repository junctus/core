//! Interface scoping for the node's own TCP sockets.
//!
//! When a neo relay runs on a host that also has a default-route VPN up (e.g. the
//! macOS app tunnelling all traffic through neo), the OS would otherwise pull the
//! relay's *own* sockets — next-hop forwarding dials, the listener's replies, and
//! an exit's clearnet splice — into that tunnel. That both defeats the point of
//! running a relay and breaks it with asymmetric routing (inbound on the physical
//! NIC, replies out the tunnel).
//!
//! The fix is to pin those sockets to a specific network interface with
//! `IP_BOUND_IF` / `IPV6_BOUND_IF` (via [`socket2`]), so their routing is decided
//! independently of the host's default route. The interface is a process-wide
//! setting ([`set_bound_interface`]) chosen once at startup from `--net-interface`,
//! because it is a property of *this node process*, not of any single connection.
//!
//! Loopback targets are never scoped, so local multi-process tests and demos —
//! where everything shares `127.0.0.1` — keep working unchanged.

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU32, Ordering};

use neo_core::{Error, Result};
use socket2::SockRef;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

/// Interface index all subsequently-created sockets bind to; `0` means unscoped.
static BOUND_IF_INDEX: AtomicU32 = AtomicU32::new(0);

/// Scope every neo TCP socket created after this call to the interface with the
/// given index (as from `if_nametoindex`). Pass `0` to clear. Process-wide.
pub fn set_bound_interface(index: u32) {
    BOUND_IF_INDEX.store(index, Ordering::Relaxed);
}

/// The interface index sockets are currently scoped to, if any.
pub fn bound_interface() -> Option<NonZeroU32> {
    NonZeroU32::new(BOUND_IF_INDEX.load(Ordering::Relaxed))
}

/// Apply the process-wide interface scope to a fresh socket, unless the target is
/// loopback (kept unscoped so local tests/demos still route). A no-op when unset.
///
/// The syscall differs by platform: Apple pins by interface **index**
/// (`IP_BOUND_IF`/`IPV6_BOUND_IF`); Linux binds by interface **name**
/// (`SO_BINDTODEVICE`), so the index is resolved to a name first.
fn scope_to_interface(sock: &TcpSocket, target: &SocketAddr) -> Result<()> {
    if target.ip().is_loopback() {
        return Ok(());
    }
    let Some(index) = bound_interface() else {
        return Ok(());
    };
    let sref = SockRef::from(sock);

    #[cfg(target_vendor = "apple")]
    match target {
        SocketAddr::V4(_) => sref.bind_device_by_index_v4(Some(index))?,
        SocketAddr::V6(_) => sref.bind_device_by_index_v6(Some(index))?,
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = target; // bind-by-name is address-family agnostic
        let name = if_name_from_index(index.get())?;
        sref.bind_device(Some(name.as_bytes()))?;
    }

    #[cfg(not(any(target_vendor = "apple", target_os = "linux", target_os = "android")))]
    {
        let _ = (sref, target, index);
        return Err(Error::Config(
            "pinning a socket to a network interface is not supported on this platform".into(),
        ));
    }

    Ok(())
}

/// Resolve an interface index to its name via `/sys/class/net/<name>/ifindex`
/// (no `libc`/`unsafe`, since this crate forbids unsafe code).
#[cfg(any(target_os = "linux", target_os = "android"))]
fn if_name_from_index(index: u32) -> Result<String> {
    let dir = std::fs::read_dir("/sys/class/net")
        .map_err(|e| Error::Config(format!("read /sys/class/net: {e}")))?;
    for entry in dir.flatten() {
        let ifindex = entry.path().join("ifindex");
        if let Ok(contents) = std::fs::read_to_string(&ifindex) {
            if contents.trim().parse::<u32>().ok() == Some(index) {
                return Ok(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    Err(Error::Config(format!(
        "no network interface has index {index}"
    )))
}

/// Dial `addr` (host:port), scoping the socket to the configured interface. A
/// drop-in for `TcpStream::connect` that honours [`set_bound_interface`]. Tries
/// each resolved address in turn, matching `TcpStream::connect`'s behaviour.
pub async fn connect_scoped(addr: &str) -> Result<TcpStream> {
    let mut last_err: Option<Error> = None;
    for target in tokio::net::lookup_host(addr).await? {
        match dial_one(target).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Config(format!("could not resolve {addr}"))))
}

async fn dial_one(target: SocketAddr) -> Result<TcpStream> {
    let sock = match target {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    scope_to_interface(&sock, &target)?;
    Ok(sock.connect(target).await?)
}

/// Bind a listener on `addr`, scoping it to the configured interface. A drop-in
/// for `TcpListener::bind` that honours [`set_bound_interface`]; accepted
/// connections inherit the scope, so their replies leave on the same interface.
pub async fn listen_scoped(addr: &str) -> Result<TcpListener> {
    let mut last_err: Option<Error> = None;
    for target in tokio::net::lookup_host(addr).await? {
        match bind_one(target) {
            Ok(listener) => return Ok(listener),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| Error::Config(format!("could not resolve bind addr {addr}"))))
}

fn bind_one(target: SocketAddr) -> Result<TcpListener> {
    let sock = match target {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    scope_to_interface(&sock, &target)?;
    sock.set_reuseaddr(true)?;
    sock.bind(target)?;
    Ok(sock.listen(1024)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test: the scope is a process-wide global, so exercising it from a
    // single sequential test avoids racing on it across parallel test threads.
    #[tokio::test]
    async fn scope_roundtrips_and_loopback_stays_connectable() {
        assert_eq!(bound_interface(), None, "starts unset");

        set_bound_interface(3);
        assert_eq!(bound_interface().map(|n| n.get()), Some(3));

        // Even with an interface set, loopback must stay unscoped and connectable
        // — this is what keeps the multi-process local tests/demos working.
        let listener = listen_scoped("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
        connect_scoped(&addr).await.unwrap();
        server.await.unwrap().unwrap();

        set_bound_interface(0);
        assert_eq!(bound_interface(), None, "cleared");
    }
}
