import requests
import re
from bs4 import BeautifulSoup

def get_html(url):
   _html = ""
   resp = requests.get(url)
   if resp.status_code == 200:
      _html = resp.text
   return _html

def get_package_name():
    search_qry = ['apps/category/FINANCE', 'search?q=은행&c=apps',
    'search?q=뱅크&c=apps', 'search?q=금융&c=apps', 'search?q=결제&c=apps',
    'search?q=핀테크&c=apps', 'search?q=투자&c=apps', 'search?q=블록체인&c=apps']

    print("[*] get package name..")
    pkg_list = list()
    for i in range(len(search_qry)):
        target_url = "https://play.google.com/store/" + search_qry[i]
        html = get_html(target_url)
        soup = BeautifulSoup(html, 'lxml')

        for item in soup.find_all("a"):
            if ('href' in item.attrs) and ('/store/apps/details?id' in item.attrs['href']):
                target = item.attrs['href']
                pkg_list.append(target[23:])

    pkg_list = list(set(pkg_list))
    print("[*] " + str(len(pkg_list)) + " package founded!")
    return pkg_list

def get_dowload_url(pkg_list=get_package_name()):
    print("[*] generate download url..")
    new_pkg_list = list()
    url_list = list()
    for item in pkg_list:
        target_url = f"https://apkpure.com/kr/{item}/"
        html = get_html(target_url)
        soup = BeautifulSoup(html, 'lxml')

        if soup.find('dd'):
            for j in soup.find('dd').find_all('a'):
                if ('href' in j.attrs) and ('download?from=details' in j.attrs['href']):
                    target = 'https://apkpure.com' + j.attrs['href']
                    url_list.append(target)
                    new_pkg_list.append(item)
                    print(target)
           
    return url_list, new_pkg_list

def download_apk(package_name, download_url):
    file_name = str(package_name) + '.apk'
    # timeout exception hadling
    try:
        r = requests.get(download_url, timeout=60)
        # save => <package name>.apk
        with open('../sample-apk/' + file_name, 'wb') as apk:
            apk.write(r.content)
    except requests.exceptions.Timeout as e:
        print('time out')
        return False
    except Exception as e:
        print(e)
        return False

    return True

def run():
    download_list, pkg_list = get_dowload_url()
    request_target = list()

    for i in download_list:
        target_url = i
        html = get_html(target_url)
        soup = BeautifulSoup(html, 'lxml')
        print("[*] " + i)
        for j in soup.find_all('a', id='download_link'):
            print(j)
            if 'download.apkpure.com' in j.attrs['href']:
                request_target.append(j.attrs['href'])
                print(j.attrs['href'])

    for i in range(len(pkg_list)):
        if download_apk(pkg_list[i], request_target[i]):

            print(f'[{i+1}/{len(pkg_list)}] {pkg_list[i]} download.. SUCCESS')
        else:
            print(f'[{i+1}/{len(pkg_list)}] {pkg_list[i]} download.. FAIL')


if __name__ == "__main__":
    run()