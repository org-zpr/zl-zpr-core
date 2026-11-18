# oidc + zpr-attr/1 trusted-service interplay fixture (zipline#81, epic #72
# E1; ported to Zodes by zl-zipline#234). oidc-file-interplay.zpl with the
# `file` decorator replaced by the networked `zpr-attr/1` attribute service:
#   - zb is a Zode whose user logs in through the fake IdP (`google`,
#     api = "oidc") as sub `user-a` (zl-zipline#233): zb's own actor then
#     carries the user's attributes.
#   - `zipline` (api = "zpr-attr/1") decorates that identity over HTTPS: the
#     reference zpr-attr-server vends dept plus the `contractor` tag, keyed
#     on user.sub.
#   - `allow contractor users to access Web.` is the ONLY statement
#     referencing a trusted-service attribute, and it references only
#     zipline's tag — so `google` survives compilation by the
#     identity-vendor retention rule (zipline#23), not by any attribute
#     reference.
#   - zc is a device-only Zode (nobody logs in on it) and provides Web.

define zode as a device with zpr.adapter.cn.

define Relay as zode with zpr.adapter.cn:relay.
define Zb as zode with zpr.adapter.cn:zb.
define Zc as zode with zpr.adapter.cn:zc.
define Vs as zode with zpr.adapter.cn:'vs.zpr'.

# Web is provided by zc's device CN; its protocol in the .zplc is ping.
define Web as a service with device.zpr.adapter.cn:zc.
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.

# The interplay under test: `contractor` resolves through the zipline
# attribute service (contractor -> #user.contractor), keyed on the identity
# attribute user.sub that `google` mints.
allow contractor users to access Web.

# Fabric plumbing: every Zode reaches the visa service as a machine, so
# the revocation leg can show that only the contractor visa went.
allow Relay to access PingableVs.
allow Zb to access PingableVs.
allow Zc to access PingableVs.
