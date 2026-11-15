"""Alerting module: channels, subscriptions, notification log."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from diysca.alerting import notify
from diysca.core import db
from diysca.scanning.feeds import SEVERITY_ORDER
from diysca.ui import (
    all_groups,
    render,
)

router = APIRouter()


@router.get("/settings/notifications")
def alerts(request: Request):
    chans = db.q("SELECT * FROM channels ORDER BY name")
    subs = db.q("SELECT s.*, c.name channel FROM subscriptions s JOIN channels c ON c.id=s.channel_id ORDER BY s.name")
    log = db.q("""SELECT n.*, c.name channel, f.vuln_id, f.package, h.name host FROM notifications n
                  JOIN channels c ON c.id=n.channel_id JOIN findings f ON f.id=n.finding_id JOIN hosts h ON h.id=f.host_id
                  ORDER BY n.sent_at DESC LIMIT 50""")
    return render(request, "alerts.html", tab="notifications", chans=chans, subs=subs, log=log, severities=SEVERITY_ORDER[2:],
                  groups=all_groups(), msg=request.query_params.get("msg"))


@router.post("/channels")
def add_channel(name: str = Form(...), url: str = Form(...)):
    db.x("INSERT INTO channels(name,url) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET url=excluded.url", (name, url))
    return RedirectResponse("/settings/notifications", 303)


@router.post("/channels/{cid}/delete")
def del_channel(cid: int):
    db.x("DELETE FROM channels WHERE id=?", (cid,))
    return RedirectResponse("/settings/notifications", 303)


@router.post("/channels/{cid}/test")
async def test_channel(cid: int):
    ch = db.q1("SELECT * FROM channels WHERE id=?", (cid,))
    ok, err = await notify.send_to_channel(ch, "[diysca] test", "Test notification from diysca. It works!")
    return RedirectResponse("/settings/notifications?" + urlencode({"msg": f"{ch['name']}: " + ("sent" if ok else err)}), 303)


@router.post("/subscriptions")
def add_sub(name: str = Form(...), channel_id: int = Form(...), host_pattern: str = Form("*"),
            package_pattern: str = Form("*"), min_severity: str = Form("LOW"), only_kev: str = Form(""),
            only_fixable: str = Form(""), sub_id: str = Form("")):
    vals = (name, channel_id, host_pattern or "*", package_pattern or "*", min_severity,
            int(bool(only_kev)), int(bool(only_fixable)))
    if sub_id:
        db.x("""UPDATE subscriptions SET name=?, channel_id=?, host_pattern=?, package_pattern=?, min_severity=?,
                only_kev=?, only_fixable=? WHERE id=?""", vals + (int(sub_id),))
    else:
        db.x("""INSERT INTO subscriptions(name,channel_id,host_pattern,package_pattern,min_severity,only_kev,only_fixable)
                VALUES (?,?,?,?,?,?,?)""", vals)
    return RedirectResponse("/settings/notifications", 303)


@router.post("/subscriptions/{sid}/delete")
def del_sub(sid: int):
    db.x("DELETE FROM subscriptions WHERE id=?", (sid,))
    return RedirectResponse("/settings/notifications", 303)


@router.post("/subscriptions/{sid}/toggle")
def toggle_sub(sid: int):
    db.x("UPDATE subscriptions SET enabled = 1 - enabled WHERE id=?", (sid,))
    return RedirectResponse("/settings/notifications", 303)


@router.post("/settings/notifications/dispatch")
async def dispatch_now():
    n = await notify.dispatch()
    return RedirectResponse("/settings/notifications?" + urlencode({"msg": f"sent {n} alerts"}), 303)
