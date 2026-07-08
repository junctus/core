// neo — iOS Packet Tunnel Provider (scaffold).
//
// Skeleton only: fill in as milestone M8 is built out. It shows where the shared
// Rust core (via UniFFI-generated bindings from `neo-ffi`) plugs into iOS's
// NetworkExtension. Requires Xcode to build.

import NetworkExtension
// import NeoFFI  // UniFFI-generated bindings for the `neo-ffi` crate

final class PacketTunnelProvider: NEPacketTunnelProvider {
    // Handle to the Rust engine; created from a stored identity.
    // private var engine: NeoEngine?

    override func startTunnel(options: [String: NSObject]?,
                             completionHandler: @escaping (Error?) -> Void) {
        // 1. Load or generate the node identity (Keychain).
        //    let secret = Keychain.loadOrCreate { generateIdentity() }   // neo-ffi
        // 2. Configure the tunnel network settings (addresses, routes, MTU).
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        // settings.ipv4Settings = ...
        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error { completionHandler(error); return }
            // 3. Start the engine and begin the packet loop.
            self?.readPackets()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                            completionHandler: @escaping () -> Void) {
        // engine?.stop()
        completionHandler()
    }

    /// Read outbound IP packets from the TUN and hand batches to the Rust core.
    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            // engine?.submitOutbound(packets)   // batched across the FFI boundary
            // let inbound = engine?.drainInbound()
            // self?.packetFlow.writePackets(inbound, withProtocols: protocols)
            self?.readPackets()
        }
    }
}
