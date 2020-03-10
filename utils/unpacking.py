import zipfile

def unzip(apkpath):
    unzip_target = zipfile.ZipFile(apkpath)
    unzip_target.extractall(apkpath + "_")


if __name__ == "__main__":
    path = input('path : ')
    unzip(path)