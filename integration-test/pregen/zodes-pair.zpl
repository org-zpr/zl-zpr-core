# Two-joiner Zode netns fixture (zl-zipline#254): see zodes-pair.zplc and
# zodes-direct.zplc, which both compile this file.
#
# The relay docks the visa service; zb and zc join through it. Each Zode
# may ping the visa service and the visa service each Zode. Between the
# joiners only Zb -> PingableZc and Zc -> PingableZb are allowed, so a ping
# reply between them shows the traffic carried the sender's own identity
# (Zodes plan W4).

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
