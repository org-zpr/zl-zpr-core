# Ping-mesh Zode netns fixture (zl-zipline#234): see zodes-ping.zplc.
#
# The relay docks the visa service; zb, zc and zd join through it. Each
# Zode may ping the visa service and the visa service each Zode, as in
# zodes-pair.zpl, and every pair of the three endpoints may ping each
# other: zode-ping-test.sh pings the full mesh.

define zode as a device with zpr.adapter.cn.

define Relay as zode with zpr.adapter.cn:relay.
define Zb as zode with zpr.adapter.cn:zb.
define Zc as zode with zpr.adapter.cn:zc.
define Zd as zode with zpr.adapter.cn:zd.
define Vs as zode with zpr.adapter.cn:'vs.zpr'.

define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableRelay as a service with device.zpr.adapter.cn:relay.
define PingableZb as a service with device.zpr.adapter.cn:zb.
define PingableZc as a service with device.zpr.adapter.cn:zc.
define PingableZd as a service with device.zpr.adapter.cn:zd.

allow Relay to access PingableVs.
allow Zb to access PingableVs.
allow Zc to access PingableVs.
allow Zd to access PingableVs.
allow Vs to access PingableRelay.
allow Vs to access PingableZb.
allow Vs to access PingableZc.
allow Vs to access PingableZd.
allow Zb to access PingableZc.
allow Zb to access PingableZd.
allow Zc to access PingableZb.
allow Zc to access PingableZd.
allow Zd to access PingableZb.
allow Zd to access PingableZc.
