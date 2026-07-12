from jinja2 import Environment, FileSystemLoader
from datetime import datetime

def build(report, outfile="shield_report_v2.html"):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("shield_report_v2.html")
    now = datetime.now()

    html = template.render(
        report=report,
        scan_date=now.strftime("%d.%m.%Y, %H:%M"),
        scan_short_date=now.strftime("%d.%m.%Y"),
        scan_time=now.strftime("%H:%M:%S")
    )

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)

    return outfile
