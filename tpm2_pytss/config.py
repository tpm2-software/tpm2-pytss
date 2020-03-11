import json
import pkgutil

CONFIG = json.loads(pkgutil.get_data(__package__, "config.json"))

SYSCONFDIR = CONFIG.get("sysconfdir", "/etc")
