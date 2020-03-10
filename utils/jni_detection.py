import os
import shutil

def search(dirname):

    try:
        filenames = os.listdir(dirname)
        for filename in filenames:
            full_filename = os.path.join(dirname, filename)
            if os.path.isdir(full_filename):
                search(full_filename)
            else:
                ext = os.path.splitext(full_filename)[-1]

                if ext == '.so': 
                    print(full_filename)
                    so_arch = full_filename.split('/')[-2]
                    so_name = full_filename.split('/')[-1]
                    shutil.copy(full_filename, f'../jni/{so_arch}/')
    except Exception as e:
        print(e)
 
search('../sample-apk/com.bpsec.andvulnapp.apk_/')