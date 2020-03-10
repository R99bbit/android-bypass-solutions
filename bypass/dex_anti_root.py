import pyjadx
import frida
import pygments
import os
import sys

# TODO 2020. 02. 26. Java Object Memory Address Checking
# TODO 2020. 02. 27. Crwaling APK files

# @param pyjadx.Jadx $app Decompiled APK or Dex Object
def hasRootCheck(app): 
    AntiRootList = set()

    # Rooting check files
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

    if app.classes: # Can code dumping?
        cmd = input('class founded, dump it?(yes/no) : ')
        if (cmd is 'yes') or (cmd is 'y'):
            dump_path = input("where I save it? : android-auto-hack/dump-code/")
            dump_path = './dump-code/' + dump_path
            try:
                if not os.path.isdir(dump_path):
                    os.mkdir(dump_path)
            except Exception as e:
                print(e)    
    
    # Extract root checker classes
    for cls in app.classes:
        if ('google' in cls.fullname) or ('android' in cls.fullname) or ('kakao' in cls.fullname) or ('facebook' in cls.fullname) or ('naver' in cls.fullname): # optimization
            continue
        else:
            if (cmd is 'yes') or (cmd is 'y'):
                cls.save(dump_path + '/' + cls.fullname + '.java') # code dump -> generate cahce
            target_code_line = cls.code.splitlines()
            for rootfile in rootFiles:
                for iter in target_code_line:
                    if rootfile in iter:
                        AntiRootList.add(cls.fullname)
                        break
    return AntiRootList

# @param pyjadx.Jadx $app Decompiled APK or Dex Object
# @param list $AntiRootList hasRootCheck($app)
def ParseMethod(app, AntiRootList):
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
    AntiRootList = AntiRootList
    AntiRootMethod = dict() # cls_name : methodlist

    # target list init
    for cls in AntiRootList:
        AntiRootMethod[cls] = list()
        cls_obj = app.get_class(cls)
        splitCode = cls_obj.code.splitlines()
        MethodList = list()

        for method in cls_obj.methods:
            tmp = list()
            tmp.append(method.decompiled_line)
            tmp.append(method.name)
            MethodList.append(tmp)

        MethodList = sorted(MethodList)

        # Method parsing and anti-root detection
        for i in range(len(MethodList)):
            currentMethod = MethodList[i][1]

            # Assign method's start-end point
            indexStart = MethodList[i][0]
            if i < len(MethodList) - 1:
                indexEnd = MethodList[i + 1][0]
            else:
                indexEnd = len(splitCode)

            # Method code parsing
            parsedMethod = ""
            for j in range(indexStart, indexEnd):
                parsedMethod += splitCode[j]
            
            # Root checker detection
            for rootfile in rootFiles:
                if rootfile in parsedMethod:
                    AntiRootMethod[cls].append(currentMethod)
                    rootFiles.append(currentMethod) # if root checker using chained routine
                    break
    return AntiRootMethod

# @param pyjadx.Jadx $app Decompiled APK or Dex Object
def Dex_Make_AntiRootBypass(app):
    jscode = ""
    AntiRootList = hasRootCheck(app)
    AntiRootMethod = ParseMethod(app, AntiRootList)
    
    # Anti-Root Detected
    if AntiRootList:
        jscode += '/* Rooting Bypass */\n'
        jscode += 'console.log("[*] Bypass Anti-Root Start...");\n'
        for i in AntiRootList: # Classes
            for j in app.get_class(i).methods: # Methods
                if (str(j.return_type) == 'boolean') and (j.name in AntiRootMethod[i]): # Is root checker?
                    jscode += 'try {\n'
                    jscode += f'    Java.use("{i}").{j.name}.implementation = function()'
                    jscode += ' {    try {   return false;   } catch(e) {    return this.' + j.name + '();   }   }\n'
                    jscode += '} catch(e) {    console.error(e);   }\n\n' # fix overload issue
        return jscode # java.lang.ClassNotFoundException
    # No Root Checker
    else:
        print("[*] Anti-Root no exist")
        return None