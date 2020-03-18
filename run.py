import pyjadx
import frida
import pygments
import pathlib
import argparse
import sys
import os
import subprocess
import re

from bypass.native_anti_root import *
from bypass.dex_anti_root import *
from analysis.payment import *
from utils.crawler import *

def a_dex_bypass_antiroot(jscode):
    try:
        tmp = Dex_Make_AntiRootBypass(app)
        if tmp is not None:
            jscode += tmp
        os.system('clear')
        print("hooking script : ")
        print(jscode + "});\n")
        return jscode
    except Exception as e:
        print(e)

def b_native_bypass_antiroot(path, jscode):
    try:
        jscode += Native_Make_AntiRootBypass(path)
        os.system('clear')
        print("hooking script : ")
        print(jscode + "});\n")
        return jscode
    except Exception as e:
        print(e)
    
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
cmd = ''
args = parser.parse_args()

print('\n[+] Choose Analysis Type')
print('[a] Single APK')
print('[b] Multiple APKs')

cmd = input('android-auto-hack> ')

while (cmd is not 'a') and (cmd is not 'b'):
    cmd = input('android-auto-hack> ')

if cmd is 'a':
    ''' Type [a] Single APK '''
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
        print('[a] dex bypass anti-root')
        print('[b] native bypass anti-root')
        print('[c] binding')
        cmd = input("\nandroid-auto-hack> ")

        if cmd is 's':
            print('\nhooking script : ')
            print(jscode)

        elif cmd is 'a':
            jscode = a_dex_bypass_antiroot(jscode)
        
        elif cmd is 'b':
            jscode = b_native_bypass_antiroot(args.f, jscode)

        elif cmd is 'c':
            c_binding(package_name, jscode)
            break
        
        elif cmd is 'clear' or 'cls':
            os.system('clear')

elif cmd is 'b':
    ''' Type [b] Multiple APKs '''
    run()