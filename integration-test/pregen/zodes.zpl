# Zodes netns fixture (zl-zipline#222): see zodes.zplc.
#
# Each Zode is its own actor (W4): its applications use the Zode's own ZPR
# address and identity. zb and zc may ping each other; that traffic
# crosses the relay. Every Zode and the visa service may ping each other.

define zode as a device with zpr.adapter.cn.

define Relay as zode with zpr.adapter.cn:relay.
define Zb as zode with zpr.adapter.cn:zb.
define Zc as zode with zpr.adapter.cn:zc.
define Vs as zode with zpr.adapter.cn:'vs.zpr'.

define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableRelay as a service with device.zpr.adapter.cn:relay.
define PingableZb as a service with device.zpr.adapter.cn:zb.
define PingableZc as a service with device.zpr.adapter.cn:zc.

allow Zb to access PingableZc.
allow Zc to access PingableZb.

allow Relay to access PingableVs.
allow Zb to access PingableVs.
allow Zc to access PingableVs.
allow Vs to access PingableRelay.
allow Vs to access PingableZb.
allow Vs to access PingableZc.
