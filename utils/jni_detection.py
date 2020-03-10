import os
import shutil

class JNI_Object:
    def __init__(self):
        self.Native_List = list()
        
    def getNativeList(self):
        return self.Native_List

    def hasJNI(self, dirname):
        try:
            filenames = os.listdir(dirname)
            for filename in filenames:
                full_filename = os.path.join(dirname, filename)
                if os.path.isdir(full_filename):
                    self.hasJNI(full_filename)
                else:
                    ext = os.path.splitext(full_filename)[-1]

                    if ext == '.so': 
                        so_arch = full_filename.split('/')[-2]
                        so_name = full_filename.split('/')[-1]
                        shutil.copy(full_filename, f'../jni/{so_arch}/')
                        self.Native_List.append(f'../jni/{so_arch}/{so_name}')
        
        except Exception as e:
            print(e)

if __name__ == '__main__':
    instance = JNI_Object()
    instance.hasJNI('../sample-apk/com.bpsec.andvulnapp.apk_/')
    print(instance.getNativeList())