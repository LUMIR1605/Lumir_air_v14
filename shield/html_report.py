from jinja2 import Environment, FileSystemLoader
from datetime import datetime

def build(report, outfile="shield_report_v2.html"):
    env = Environment(loader=FileSystemLoader("templates"))
    template = env.get_template("shield_report_v2.html")

    html = template.render(
        report=report,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M")
    )

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)

    return outfile
