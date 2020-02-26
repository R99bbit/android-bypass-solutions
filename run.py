import pyjadx
import frida
import pygments
import pathlib
import argparse
import sys
import os

from bypass.anti_root import *
from analysis.payment import *


def a_bypass_antiroot(jscode):
    jscode += MakeBypassScript(app)
    os.system('clear')
    print("hooking script : ")
    print(jscode + "});\n")
    return jscode

# start application
# @param String $package package name
# @param String $jscode hooking script
def b_binding(package, jscode):
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

parser.add_argument('-p', required=True, help='package name')
parser.add_argument('-f', required=True, help='apk file path')

args = parser.parse_args()

# jadx binding
jadx = pyjadx.Jadx()
app_path = pathlib.Path(args.f).resolve().absolute()
app = jadx.load(app_path.as_posix())


# generate frida hooking script
jscode = 'Java.perform(function() {\n'

while True:
    print('\n========== ' + args.p + ' Attached!! ==========')
    print('[s] show hooking script')
    print('[a] bypass anti-root(generate script)')
    print('[b] binding')
    cmd = input("\nandroid-auto-hack> ")

    if cmd is 's':
        print('\nhooking script : ')
        print(jscode)

    elif cmd is 'a':
        jscode = a_bypass_antiroot(jscode)

    elif cmd is 'b':
        b_binding(args.p, jscode)
        break
    
    elif cmd is 'clear' or 'cls':
        os.system('clear')
    