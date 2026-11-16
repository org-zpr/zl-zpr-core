# Zode login netns fixture (zl-zipline#233): see zodes-login.zplc.
#
# The relay and zb are Zodes linked to each other, as in zodes.zpl; the visa
# service is docked on the relay. zb's own actor reaches the visa service as
# a device (the device flow), and reaches the relay only while a user is
# logged in on zb (the user flow): the rule names the user's OIDC subject,
# which zb's actor carries only between `ph-cli connect` and `ph-cli logout`.

define zode as a device with zpr.adapter.cn.

define Relay as zode with zpr.adapter.cn:relay.
define Zb as zode with zpr.adapter.cn:zb.
define Vs as zode with zpr.adapter.cn:'vs.zpr'.

# The fake-IdP user who logs in on zb (fake-idp.py --sub in zpr-zb).
define ZbUser as users with oidc-subject:'user-zb'.

define PingableVs as a service with device.zpr.adapter.cn:'vs.zpr'.
define PingableRelay as a service with device.zpr.adapter.cn:relay.

allow Relay to access PingableVs.
# The device flow: zb as a machine, logged in or not.
allow Zb to access PingableVs.
# The user flow: only an actor carrying the user's attribute.
allow ZbUser to access PingableRelay.
