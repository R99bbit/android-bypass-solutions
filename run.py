from bypass.anti_root import *

import pyjadx
import frida
import pygments
import pathlib
import os

# apk binding
jadx = pyjadx.Jadx()
app_path = pathlib.Path("./sample-apk/panelpower.apk").resolve().absolute()
app = jadx.load(app_path.as_posix())

print('Hooking Script : \n' + MakeBypassScript(app))