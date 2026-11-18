# Rejoin-after-expiry Zode netns fixture (zl-zipline#271): see
# zodes-rejoin.zplc. zodes-pair.zpl, plus a UDP/53 service on zc that Zb
# may reach only while it has a `device.hostname` attribute. That attribute
# comes from a file trusted service with a short lifetime, so every visa
# for the service expires within a test run, the way the DNS visas of a
# ZIPLINE network do (zl-zipline#271).

define zode as a device with zpr.adapter.cn.

define Relay as zode with zpr.adapter.cn:relay.
define Zb as zode with zpr.adapter.cn:zb.
define Zc as zode with zpr.adapter.cn:zc.
define Vs as zode with zpr.adapter.cn:'vs.zpr'.

define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableRelay as a service with device.zpr.adapter.cn:relay.
define PingableZb as a service with device.zpr.adapter.cn:zb.
define PingableZc as a service with device.zpr.adapter.cn:zc.

allow Relay to access PingableVs.
allow Zb to access PingableVs.
allow Zc to access PingableVs.
allow Vs to access PingableRelay.
allow Vs to access PingableZb.
allow Vs to access PingableZc.
allow Zb to access PingableZc.
allow Zc to access PingableZb.

define DnsZc as a service with device.zpr.adapter.cn:zc.
allow zpr.adapter.cn:zb and device.hostname: devices to access DnsZc.
