"""Alerting: channels (Apprise), subscriptions, alert messages."""
from diysca.core import events
from diysca.core.modules import Module


def _setup():
    from diysca.alerting import notify
    events.on("scan.finished", notify.on_scan_finished)
    events.on("scans.finished", notify.on_scans_finished)
    events.on("mitigation.status", notify.on_mitigation_status)


MODULE = Module(
    name="alerting", title="Alerting", description="Sends new findings and mitigation updates to ntfy, e-mail, Matrix, Slack and more.",
    routes="diysca.alerting.routes",
    settings_tabs=[("notifications", "/settings/notifications", "Notifications", 20)],
    setup=_setup,
)
