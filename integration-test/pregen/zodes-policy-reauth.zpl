# Policy-install re-authentication fixture for Zodes (zipline#124, ported to
# Zodes by zl-zipline#234): see zodes-policy-reauth.zplc, which with its two
# variants compiles this file.
#
# The relay hosts the visa service; zb and zc join through it. Each Zode
# re-authenticates differently when a policy install obliges it to:
#   - zb is DEVICE-ONLY: nobody logs in on it, so it re-authenticates the
#     node in place with its bootstrap key (zipline#121, K2).
#   - zc has a user logged in through a resident auth agent, so it answers
#     with a silent renewal of that login (zl-zipline#233, g116 q3): its
#     bootstrap signature plus a refreshed OIDC token.
# The relay re-authenticates in place, like zb.

define zode as a device with zpr.adapter.cn.

define Relay as zode with zpr.adapter.cn:relay.
define Zb as zode with zpr.adapter.cn:zb.
define Zc as zode with zpr.adapter.cn:zc.
define Vs as zode with zpr.adapter.cn:'vs.zpr'.

# The fake-IdP user who logs in on zc (fake-idp.py --sub in zpr-zc).
define ZcUser as users with oidc-subject:'user-zc'.

define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableZb as a service with device.zpr.adapter.cn:zb.

# The user flow under test: zc's logged-in user reaches zb. It carries the
# continuous ping across the installs, and it dies with zb in leg 3.
allow ZcUser to access PingableZb.

# Every Zode reaches the visa service as a machine. zc's device flow is the
# leg-3 probe that zc is unaffected when zb is disconnected.
allow Relay to access PingableVs.
allow Zb to access PingableVs.
allow Zc to access PingableVs.
