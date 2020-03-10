import pyjadx
import frida
import pygments
import pathlib
import argparse
import sys
import os
import subprocess
import re

from bypass.dex_anti_root import *
from analysis.payment import *


def a_bypass_antiroot(jscode):
    try:
        jscode += Dex_Make_AntiRootBypass(app)
        os.system('clear')
        print("hooking script : ")
        print(jscode + "});\n")
        return jscode
    except Exception as e:
        print(e)
# @param pyjadx.Jadx $app Decompiled APK or Dex Object
def b_search_hooking_point(app):
    # os.system('clear')
    payment_class = PaymentDetection()
    getter_class = FindingGetter(app, payment_class)
    print('[*] payment class list')
    for i in payment_class:
        print(i)

    print('\n[*] getter list')
    for j in getter_class:
        print(j)

# start application
# @param String $package package name
# @param String $jscode hooking script
def c_binding(package, jscode):
    jscode += '\n});'
    def on_message(message, data):
        print("{} -> {}".format(message, data))

    try:
        device = frida.get_usb_device(timeout = 10)
        pid = device.spawn([package])
        print("[+] Target App is Running..")
        process = device.attach(pid)
        device.resume(pid)
        script = process.create_script(jscode)
        script.on('message', on_message)
        print("[+] Running Frida")
        script.load()
        sys.stdin.read()

    except Exception as e:
        print(e)

# argument parsing
parser = argparse.ArgumentParser(description='usage test')
parser.add_argument('-f', required=True, help='apk file path')

# extract package name using regular expression
args = parser.parse_args()

res = subprocess.check_output(['aapt', 'dump', 'badging', args.f])
res = str(res)

m = re.search("name='(.*?)'", res)
package_name = m.group(1)

# jadx binding
jadx = pyjadx.Jadx()
app_path = pathlib.Path(args.f).resolve().absolute()
app = jadx.load(app_path.as_posix())


# generate frida hooking script
jscode = 'Java.perform(function() {\n'

while True:
    print('\n========== ' + package_name + ' Attached!! ==========')
    print('[s] show hooking script')
    print('[a] bypass anti-root(generate script)')
    print('[b] search hooking point')
    print('[c] binding')
    cmd = input("\nandroid-auto-hack> ")

    if cmd is 's':
        print('\nhooking script : ')
        print(jscode)

    elif cmd is 'a':
        jscode = a_bypass_antiroot(jscode)
    
    elif cmd is 'b':
        b_search_hooking_point(app)

    elif cmd is 'c':
        c_binding(package_name, jscode)
        break
    
    elif cmd is 'clear' or 'cls':
        os.system('clear')
    