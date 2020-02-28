import requests
import re
from bs4 import BeautifulSoup

def get_html(url):
   _html = ""
   resp = requests.get(url)
   if resp.status_code == 200:
      _html = resp.text
   return _html

if __name__ == "__main__":
    target_url = "https://apkpure.com/kr/ma-banque/fr.creditagricole.androidapp/download?from=details"
    html = get_html(target_url)
    soup = BeautifulSoup(html, 'lxml')


    for j in soup.find_all('a', id='download_link'):
        print(j)
        if 'download.apkpure.com' in j.attrs['href']:
            print(j.attrs['href'])