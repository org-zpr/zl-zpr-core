# Zode links netns fixture (zl-zipline#250): see zodes.zplc.
#
# The relay and zb are Zodes linked to each other; the visa service is
# docked on the relay. The rules let each of them ping the others, so the
# visa service has a policy to evaluate; zode-link-test.sh checks links and
# link-state reports, not traffic.

define zode as a device with zpr.adapter.cn.

define Relay as zode with zpr.adapter.cn:relay.
define Zb as zode with zpr.adapter.cn:zb.
define Vs as zode with zpr.adapter.cn:'vs.zpr'.

define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableRelay as a service with device.zpr.adapter.cn:relay.
define PingableZb as a service with device.zpr.adapter.cn:zb.

allow Relay to access PingableVs.
allow Zb to access PingableVs.
allow Vs to access PingableRelay.
allow Vs to access PingableZb.
allow Zb to access PingableRelay.
