# sample python file
import requests

def hello():
    r = requests.get('https://httpbin.org/get')
    return r.status_code

if __name__ == '__main__':
    print('hello', hello())
