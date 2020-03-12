import sys


from utils.ext_string import *
from utils.jni_detection import *
from utils.unpacking import *

# @param String $filepath Target APK Path
def Native_Detection(filepath):
    # Unpacking APK
    unzip(filepath) # Unpacking Target APK -> filepath_
    print('[*] APK unpacked path -> ' + filepath + '_/')
    
    # JNI Detection
    instance = JNI_Object()
    instance.hasJNI(filepath + "_")

    if not instance.Native_List:
        print('[*] shared object not found')
        return

    else:
        cmd = None
        print('[*] shared object detected -> ' + str(len(instance.Native_List)) + ' cases')
        for i in range(len(instance.Native_List)):
            print(f'[{i+1}] {instance.Native_List[i]}')

        print('\n[*] Choose Your Architecture')
        print('[a] arm64-v8a')
        print('[b] armeabi-v7a')
        print('[c] armeabi')
        print('[d] x86_64')
        print('[e] x86')

        cmd = input('android-auto-hack> ')
        while not('a' <= cmd and cmd <= 'e'):
            cmd = input('android-auto-hack> ')
        
    return instance.Native_List, cmd


# @param List $NativeList Native Libc List
def hasRootCheck(NativeList, cmd):
    RootingLibc = list() # Anti Rooting Loginc Exist List
    rootFiles = [
            '/sbin/su', '/system/su',
            '/system/bin/su', '/system/sbin/su',
            '/system/xbin/su', '/system/xbin/mu',
            '/system/bin/.ext/.su', '/system/usr/su-backup',
            '/data/data/com.noshufou.android.su', '/system/app/Superuser.apk',
            '/system/app/su.apk', '/system/bin/.ext',
            '/system/xbin/.ext', '/data/local/xbin/su',
            '/data/local/bin/su', '/system/sd/xbin/su',
            '/system/bin/failsafe/su', '/data/local/su',
            '/su/bin/su', 'busybox', 'Emulator', '"su"'
        ]
    
    # ready to analysis
    arch = None
    TargetLibc = list()
    if cmd is 'a':
        arch = 'arm64-v8a'   
    elif cmd is 'b':
        arch = 'armeabi-v7a'
    elif cmd is 'c':
        arch = 'armeabi'
    elif cmd is 'd':
        arch = 'x86_64'
    elif cmd is 'e':
        arch = 'x86'

    for iter in NativeList:
        TargetLibc.append(f'./jni/{arch}/' + iter.split('/')[-1])
    
    TargetLibc = list(set(TargetLibc))

    print(TargetLibc)

    # Extract Inner String
    for iter in TargetLibc: # Target Native Libc Iteration
        tmp = list()
        print('\n==========> ' + str(iter.split('/')[-1]))
        
        try:
            for string in extract_strings(iter):
                tmp.append(string)

            for file in rootFiles:
                if file in tmp:
                    print(file)
                    RootingLibc.append(iter.split('/')[-1])
        except Exception as e:
            pass

    RootingLibc = list(set(RootingLibc))

    return RootingLibc


# List $RootingLibc Anti Root Library List
def Native_Make_AntiRootBypass(filepath):
    NativeList, cmd = Native_Detection(filepath)
    RootingLibc = hasRootCheck(NativeList, cmd)

    jscode = ''
    native_func_ret = {'fopen':'ptr("0x0")', 'access':'-1'}
    for libc in RootingLibc:
        for func in native_func_ret:
            jscode += f'\n    Interceptor.attach(Module.findExportByName("{libc}", "{func}"),' + ' {\n'
            jscode += '         onEnter: function(args) {   console.log("[*] ' + func + '() Called");   },\n'
            jscode += '         onLeave: function(retval) {    ' + f'retval.replace({native_func_ret[func]}); ' + f'console.log("[*] {func} returns " + retval);' + '   }\n'
            jscode += '    });\n'

    return jscode

if __name__ == '__main__':
    print(Native_Make_AntiRootBypass('../sample-apk/com.bpsec.andvulnapp.apk'))