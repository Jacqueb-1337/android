# Net-Merge Root for Android

Experimental root-only fork of [net-merge/android](https://github.com/net-merge/android).

**Goal:** load-balance Wi-Fi and mobile-data connections without occupying Android's
single VpnService slot. Tailscale or another VPN app can stay active.

This is **not** yet certified for daily use. Android OEMs modify policy routing.
Use only on a rooted phone, and test with local USB ADB access before enabling
it for the first time. A remote ADB connection may be cut if a policy rule behaves
differently from the tested device. The helper automatically cleans up policy
rules when the app stops or its local Unix socket disconnects.

## What's different

- Removes VpnService and its VPN permission request entirely.
- Adds a small native root helper to create a TUN interface, configure a
  separate routing table and transfer the TUN descriptor into the ordinary
  unprivileged Android process using SCM_RIGHTS.
- Keeps the original Go flow-balancing engine and existing Compose UI.
- Keeps Android's normal VPN routing at priority 13000 ahead of the root
  balancing rule at priority 23123. Normal physical-network fallback rules
  come after priority 23123.
- Matches **unmarked** locally originated packets only. Sockets explicitly
  bound to Wi-Fi or cellular by the Go engine carry Android network fwmarks,
  and do not get re-captured. This is crucial to preventing routing loops.
- Preserves RFC1918 LAN destinations, link-local, and tailnet addresses with
  throw routes (unless Android's VPN routing already claims them).
- Uses a different Android package ID (org.netmerge.android.root), so it can
  coexist with the official app.
- A background privileged helper holds the routing rules for the life of an
  authenticated Unix socket. Normal stop or app crash removes them.

## VPN coexistence: important limitations

This design does **not** bypass Android's existing VPN or decrypt the VPN's
traffic. Android selects a route through Tailscale **before** the new Net-Merge
root rule. If the VPN is configured only for tailnet destinations, other
unmarked internet flows may be balanced across Wi-Fi and cellular while
tailnet flows still use Tailscale.

If Tailscale runs as a **full-tunnel exit node**, it may claim all internet
traffic before Net-Merge sees it, so the traffic will remain within the VPN
and will not be balanced by the Net-Merge engine. A WireGuard/Tailscale tunnel
typically uses one UDP socket per peer, and Net-Merge's per-flow engine cannot
split a single encrypted UDP flow to double its speed.

The exact route ordering is device- and OS-dependent, and must be verified
on each ROM. Other root firewall/VPN applications may conflict with the
custom priority 23123 and table 32013.

## Build

Requires Go 1.27 or later, Java 17, Android SDK and an Android NDK.

On Linux:
1. Set ANDROID_HOME and ANDROID_NDK_HOME.
2. Run bash scripts/build-go.sh.
3. Run bash scripts/build-root-helper.sh.
4. Run ./gradlew assembleDebug.

GitHub Actions performs these steps and provides build artifacts. The
release variant without signing secrets uses the debug signing key.

## Testing before daily use

1. Keep local USB ADB available. Do not test over a remote-only Tailscale link.
2. Start Tailscale. Verify access to a tailnet IP and a public IP.
3. Install this root variant separately from the official Net-Merge.
4. Start root mode and grant Magisk root permission.
5. Check ip rule show for table 32013, and ip route show table 32013.
6. Verify tailnet access, a LAN IP, public DNS, and public internet.
7. Generate multiple independent downloads and confirm both interface
   counters increase. Single-flow downloads are not expected to aggregate.
8. Stop merging; verify the rule at priority 23123 and table 32013 are gone.

When issues occur, stop the app. If its socket and root helper were both
killed unexpectedly, recover from USB ADB:

    su -c 'ip -4 rule del pref 23123 fwmark 0x0/0x1ffff iif lo lookup 32013'
    su -c 'ip -6 rule del pref 23123 fwmark 0x0/0x1ffff iif lo lookup 32013'

These delete only this fork's specific rules. The interface disappears when
the last descriptor is closed. See root helper source for detailed cleanup.

## License

MIT, consistent with the original upstream project. See LICENSE.

