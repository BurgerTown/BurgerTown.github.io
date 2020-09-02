import os
import time
import gzip
import requests
import hmac
import hashlib
import urllib
from config import HOST, SECRETKEY, SECRETID
FILE_EXT = ['.css', '.js', '.webmanifest', '.xml', '.png']
FOLDERS = ['css', 'js', 'images', 'custom_js']
ABS_PATH = os.path.abspath(os.path.dirname(__file__))


def main():
    for file in os.listdir(ABS_PATH):
        file_path = os.path.join(ABS_PATH, file)
        if os.path.isfile(file_path):
            upload_file(os.path.join(ABS_PATH, file))
    for folder in FOLDERS:
        for path, dirs, files in os.walk(os.path.join(ABS_PATH, folder)):
            for file_name in files:
                upload_file(os.path.join(path, file_name))


def get_relative_path(file_path):
    common_prefix = os.path.commonprefix(
        [ABS_PATH, os.path.abspath(file_path)])
    relative_path = os.path.relpath(file_path, common_prefix)
    relative_path = relative_path.replace('\\', r'/')
    return relative_path


def constract_headers(path, Headers):
    Headers['Host'] = HOST

    # StartTimestamp;EndTimestamp
    KeyTime = f'{int(time.time())-60};{int(time.time())+3000}'
    SignKey = hmac.new(SECRETKEY.encode('utf-8'),
                       KeyTime.encode('utf-8'), hashlib.sha1).hexdigest()

    # HttpHeaders, HeaderList
    HttpHeaders, HeaderList = [], []
    KeyList = sorted(Headers)
    for key in KeyList:
        value = urllib.parse.quote(Headers[key]).replace('/', '%2F')
        HttpHeaders.append(f'{key.lower()}={value}')
        HeaderList.append(key.lower())
    HttpHeaders = '&'.join(HttpHeaders)
    HeaderList = ';'.join(HeaderList)

    # [HttpMethod]\n[HttpURI]\n[HttpParameters]\n[HttpHeaders]\n
    HttpURI = f'/{path}'
    HttpString = f'put\n{HttpURI}\n\n{HttpHeaders}\n'
    sha1 = hashlib.sha1()
    sha1.update(HttpString.encode('utf-8'))
    sha1_http_string = sha1.hexdigest()
    StringToSign = f'sha1\n{KeyTime}\n{sha1_http_string}\n'
    Signature = hmac.new(SignKey.encode('utf-8'),
                         StringToSign.encode('utf-8'), hashlib.sha1).hexdigest()
    Authorization = 'q-sign-algorithm={}&q-ak={}&q-sign-time={}&q-key-time={}&q-header-list={}&q-url-param-list={}&q-signature={}'.format(
        'sha1', SECRETID, KeyTime, KeyTime, HeaderList, '', Signature
    )

    Headers['Authorization'] = Authorization
    return Headers


def upload_file(file_path):
    if os.path.splitext(file_path)[1] in FILE_EXT:
        path = get_relative_path(file_path)
        if os.path.splitext(file_path)[1] == '.png':
            headers = {'Cache-Control': 'max-age=36000'}
            headers = constract_headers(path, headers)
            with open(file_path, 'rb') as f:
                content = f.read()
        else:
            headers = {'Cache-Control': 'max-age=36000',
                       'Content-Encoding': 'gzip'}
            headers = constract_headers(path, headers)
            with open(file_path, 'r') as f:
                content = gzip.compress(f.read().encode())
        link = f'https://{HOST}/{path}'
        response = requests.put(link, headers=headers, data=content)
        if response.status_code == 200:
            print('UPLOADED: {}'.format(file_path))
        else:
            print('ERROR CODE: {}'.format(response.code()))
    else:
        return


if __name__ == "__main__":
    main()
