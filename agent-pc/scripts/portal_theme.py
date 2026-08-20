"""Shared look for the camera portal, lifted from the guest wifi splash page.

Values are taken from /etc/opennds/htdocs/splash.css on the router rather than
eyeballed, so the two pages are actually the same design instead of merely
similar: brick #8a3c25, cream card #f6ecd6, gold border #b8893b, dark brick
#7a2e19 for type and buttons, Georgia for headings and Arial for controls.

Kept in one module so a colour changes in one place. The captive portal is on
the router and this is on the agent, so they cannot literally share a
stylesheet - this is the seam where they would otherwise drift apart.
"""

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:Georgia,'Times New Roman',serif;min-height:100vh;
background:#8a3c25;
background-image:linear-gradient(rgba(58,20,10,.28),rgba(40,14,8,.4)),
 repeating-linear-gradient(90deg,rgba(255,220,190,.06) 0 40px,rgba(0,0,0,.2) 40px 42px),
 repeating-linear-gradient(0deg,rgba(255,220,190,.05) 0 20px,rgba(0,0,0,.22) 20px 22px);
display:flex;align-items:flex-start;justify-content:center;padding:18px}
.card{width:100%;max-width:430px;background:#f6ecd6;border:6px solid #b8893b;
border-radius:16px;box-shadow:0 12px 30px rgba(0,0,0,.4);padding:26px 22px;
text-align:center;color:#3a2214;margin:auto}
.card.wide{max-width:1100px;text-align:left}
h1{font-size:34px;font-weight:900;color:#7a2e19;letter-spacing:-.5px;line-height:1.05}
.sub{font-family:Arial,sans-serif;font-size:13px;letter-spacing:5px;color:#8a3c25;
margin:6px 0 14px;font-weight:700;text-transform:uppercase}
.lead{font-size:18px;color:#7a2e19;margin:8px 0 16px;font-style:italic}
.err{background:#7a2e19;color:#f6ecd6;padding:9px 11px;border-radius:6px;margin:0 0 12px;
font-family:Arial,sans-serif;font-size:14px;text-align:left}
.ok{background:#3f6b3a;color:#f6ecd6;padding:9px 11px;border-radius:6px;margin:0 0 12px;
font-family:Arial,sans-serif;font-size:14px;text-align:left}
.lbl{display:block;font-family:Arial,sans-serif;font-size:12px;letter-spacing:2px;
text-transform:uppercase;color:#8a6a3a;margin:10px 0 5px;text-align:left}
input,select{width:100%;font-family:Arial,sans-serif;font-size:16px;padding:11px 12px;
border:2px solid #b8893b;border-radius:8px;background:#fffaf0;color:#2a1c10}
input:focus,select:focus{outline:none;border-color:#7a2e19}
.btn{display:block;box-sizing:border-box;width:100%;background:#7a2e19;color:#f6ecd6;
border:0;border-radius:999px;padding:14px;font-family:Arial,sans-serif;font-size:17px;
font-weight:700;letter-spacing:1px;text-align:center;text-decoration:none;
box-shadow:0 3px 0 #521d0f;cursor:pointer;margin-top:18px}
.btn:active{transform:translateY(2px);box-shadow:0 1px 0 #521d0f}
.btn.sm{width:auto;display:inline-block;padding:8px 16px;font-size:14px;margin:0 4px 0 0}
.btn.ghost{background:transparent;color:#7a2e19;border:1.5px solid #b8893b;box-shadow:none}
.alt{font-family:Arial,sans-serif;font-size:13.5px;color:#6d5636;margin-top:16px;
padding-top:13px;border-top:1px solid #cbb384}
.alt a{color:#7a2e19;font-weight:700;text-decoration:none}
.foot{font-family:Arial,sans-serif;font-size:11.5px;color:#8a3c25;margin-top:16px;
line-height:1.5;text-align:center}
.note{font-family:Arial,sans-serif;font-size:12.5px;line-height:1.5;text-align:left;
color:#4a382a;background:#fffaf0;border:1px solid #cbb384;border-radius:8px;
padding:11px 13px;margin:12px 0}
hr{border:0;border-top:1px solid #cbb384;margin:14px 0}
table{width:100%;border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px}
th{text-align:left;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;
color:#8a6a3a;padding:8px 10px;border-bottom:2px solid #cbb384}
td{padding:10px;border-bottom:1px solid #e2d3b4;color:#3a2214}
.pill{display:inline-block;font-family:Arial,sans-serif;font-size:11px;font-weight:700;
letter-spacing:.5px;text-transform:uppercase;padding:3px 9px;border-radius:999px}
.pill.pending{background:#c98a2e;color:#2a1c10}
.pill.approved{background:#3f6b3a;color:#f6ecd6}
.pill.denied{background:#7a2e19;color:#f6ecd6}
"""
