import base64
import json
import time
import json5
import ddddocr
import requests
import datetime
from Crypto.Cipher import AES

from com.AEScryptor import AEScryptor

url = "http://gwsxapp.gzzjzhy.com/"

# 读取账号信息
def readJsonInfo():
    with open('user2.json', "r", encoding='utf-8') as json_file:
        data = json5.load(json_file)
    json_file.close()
    return data


# 设置通用请求头
def getHeader():
    return {
        'user-agent': 'Mozilla/5.0 (Linux; Android 9; V1916A Build/PQ3A.190705.003; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.114 Mobile Safari/537.36 uni-app Html5Plus/1.0 (Immersed/24.0)',
        'Content-Type': 'application/json',
        'Accept-Encoding': 'gzip',
        'Connection': 'Keep-Alive',
        'Host': 'gwsxapp.gzzjzhy.com'
    }


# 打卡上下班
def clock_in_out(userInfo, enterpriseId, token):
    location = userInfo['location']
    headers = getHeader()
    headers['token'] = token
    data = {
        "latitude": location['latitude'],
        "locationName": location['address'],
        "locationCode": "",
        "longitude": location['longitude'],
        "enterpriseId": enterpriseId,
        "listPhoto": [],
        "latitude2": location['latitude'],
        "longitud2": location['longitude'],
        "checkRange": 10000
    }
    response = requests.post(url + "api/workClock/punchClock", data=json.dumps(data, separators=(',', ':')),
                             headers=headers)
    if response.status_code == 200:
        responseJson = json5.loads(response.text)
        if responseJson['code'] == 0:
            print(responseJson['msg'] + "===" + userInfo['token']['username'])
        else:
            print("打卡失败：" + responseJson['msg'] + "====code：" + str(responseJson['code']))
    else:
        print("打卡请求失败！")


# 获取登录用户信息 api/user/getLoginUser
def getLoginUser(token, userInfo):
    headers = getHeader()
    headers['token'] = token
    response = requests.get(url + "api/user/getLoginUser", headers=headers)
    if response.status_code == 200:
        responseJson = json5.loads(response.text)
        if responseJson['code'] == 0:
            data = responseJson['data']
            print("获取登录用户信息成功！！！")
            clock_in_out(userInfo, data['enterpriseId'], data['token'])
        else:
            print("获取登录用户信息失败：" + responseJson['msg'] + "====code：" + str(responseJson['code']))
    else:
        print("获取登录用户信息请求请求失败！")


# 登录 api/user/login
def login(userInfo, captchaVerification):
    data = {
        "phonenumber": userInfo['token']['username'],
        "password": userInfo['token']['password'],
        "captchaVerification": captchaVerification
    }
    headers = getHeader()
    headers['token'] = ''
    response = requests.post(url + "api/user/login", data=json.dumps(data, separators=(',', ':')), headers=headers)
    if response.status_code == 200:
        responseJson = json5.loads(response.text)
        if responseJson['code'] == 0:
            print("登录成功！！！")
            getLoginUser(responseJson['data']['token'], userInfo)
        else:
            print("登录失败：" + responseJson['msg'] + "====code：" + str(responseJson['code']))
    else:
        print("登录请求请求失败！")


# 根据获取的验证码效验验证码/captcha/check
def checkCaptcha(secretKey, token, jsonXy, userInfo):
    iv = b"0000000000000000"
    # 计算pointJson的值
    if secretKey != '':
        aes = AEScryptor(secretKey.encode(), AES.MODE_ECB, iv, paddingMode="PKCS7Padding", characterSet='utf-8')
    else:
        aes = AEScryptor(b'XwKsGlMcdPMEhR1B', AES.MODE_ECB, iv, paddingMode="PKCS7Padding", characterSet='utf-8')
    rData = aes.encryptFromString(jsonXy).toBase64()
    data = {
        "captchaType": "blockPuzzle",
        "pointJson": rData,
        "token": token
    }
    response = requests.post(url + "/captcha/check", data=json.dumps(data, separators=(',', ':')), headers=getHeader())
    if response.status_code == 200:
        responseJson = json5.loads(response.text)
        if responseJson['repCode'] == '0000' and responseJson['repCode']:
            print("效验验证码成功！！！")
            # 拼接字符串
            str1 = token + "---" + jsonXy
            # 加密字符串
            captchaVerification = aes.encryptFromString(str1).toBase64()
            login(userInfo, captchaVerification)
        else:
            # 效验失败重新验证（效验存在失败的情况）
            time.sleep(2)
            print("效验失败重新效验")
            getCaptcha(userInfo)
    else:
        print("效验验证码请求失败！")


# 获取验证码并识别出需要移动的位置/captcha/get
def getCaptcha(userInfo):
    # 获取当前时间戳
    now_time = datetime.datetime.now()
    timeStamp = int(time.mktime(now_time.timetuple()) * 1000.0 + now_time.microsecond / 1000.0)
    data = {
        "captchaType": "blockPuzzle",
        "clientUid": "slider-fdd237a3-944d-4f9a-88f0-73b9fb4ff217",
        "ts": timeStamp
    }
    # 发送网络请求
    response = requests.post(url + "/captcha/get", data=json.dumps(data, separators=(',', ':')), headers=getHeader())
    if response.status_code == 200:
        # 转成json对象
        responseJson = json5.loads(response.text)
        if responseJson['repCode'] == '0000':
            base64Target = base64.b64decode(responseJson['repData']['jigsawImageBase64'].encode())
            base64Background = base64.b64decode(responseJson['repData']['originalImageBase64'].encode())
            location = Identification_captCHA(base64Target, base64Background) + 9
            X = 310 * location / 330
            Xy = {
                "x": X,
                "y": 5
            }
            jsonXy = json.dumps(Xy, separators=(',', ':'))
            checkCaptcha(responseJson['repData']['secretKey'], responseJson['repData']['token'], jsonXy, userInfo)
        else:
            print("获取验证码失败！" + responseJson['repMsg'])
            return 'error'
    else:
        print("获取验证码请求失败！")


# 识别验证码
def Identification_captCHA(target, background):
    det = ddddocr.DdddOcr(det=False, ocr=False, show_ad=False)
    res = det.slide_match(target, background)
    return res['target'][0]


# 入口
if __name__ == '__main__':
    # 读取账号
    users = readJsonInfo()['user']
    # 循环遍历账号
    for user in users:
        getCaptcha(user)
        print("准备下个账号")
        time.sleep(1.5)
    print("没有账号了")
