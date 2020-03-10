import zipfile

def unzip(apkpath):
    try:
        unzip_target = zipfile.ZipFile(apkpath)
        unzip_target.extractall(apkpath + "_")
    except Exception as e:
        print(e)


if __name__ == "__main__":
    path = input('path : ')
    unzip(path)