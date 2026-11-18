# oidc + file trusted-service interplay fixture (zipline#27, epic #22
# finale), on Zodes: see oidc-file-interplay.zplc.
#
# The zipline#22 policy (rationale: zl-zpr-dev-context/docs/VISA_SERVICE.md,
# "Design decisions") on the zodes-login.zpl layout:
#   - a user logs in on zb through the fake IdP (`google`, api = "oidc") as
#     sub `user-a`, and zb's own actor carries the user's attributes;
#   - `happyfile` (api = "file") decorates that identity: its JSON is keyed
#     on user.sub and vends hair_color plus the `lazy` tag;
#   - `allow lazy users to access Web.` is the ONLY statement referencing a
#     trusted-service attribute, and it references only happyfile's tag,
#     so `google` survives compilation by the identity-vendor retention
#     rule (zipline#23), not by any attribute reference;
#   - the relay, a device-only Zode, provides Web.

define zode as a device with zpr.adapter.cn.

define Relay as zode with zpr.adapter.cn:relay.
define Zb as zode with zpr.adapter.cn:zb.
define Vs as zode with zpr.adapter.cn:'vs.zpr'.

# Web is the relay's ping service.
define Web as a service with device.zpr.adapter.cn:relay.
define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.

# The interplay under test: `lazy` resolves through the happyfile trusted
# service (lazy -> #user.lazy), keyed on the identity attribute user.sub
# that `google` mints.
allow lazy users to access Web.

# The device flows, logged in or not.
allow Relay to access PingableVs.
allow Zb to access PingableVs.
