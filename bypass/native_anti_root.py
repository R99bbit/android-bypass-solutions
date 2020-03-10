import sys

sys.path.append('../utils/')

from ext_string import *
from jni_detection import *
from unpacking import *

# @param String $filepath Target APK Path
def Native_Detection(filepath):
    # Unpacking APK
    unzip(filepath) # Unpacking Target APK -> filepath_
    print('[*] APK unpacked path -> ' + filepath + '_')
    
    # JNI Detection
    instance = JNI_Object()
    instance.hasJNI(filepath + "_")

    if not instance.Native_List:
        print('[*] shared object not found')
        return

    else:
        print('[*] shared object detected -> ' + str(len(instance.Native_List)))
        hasRootCheck(instance.Native_List)

# @param List $NativeList Native Libc List
def hasRootCheck(NativeList):
    # Extract Inner String
    for file in NativeList:
        print(file)
        for string in extract_strings(file):
            print(string)

    # TODO if target file has rooting-strings -> bypass
    
def Native_Make_AntiRootBypass():
    pass


if __name__ == '__main__':
    Native_Detection('../sample-apk/com.bpsec.andvulnapp.apk')