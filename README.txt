## 其他 ##
python3 code4.py
python3 code5.py    # 5-2 有機會跑不出來，要多刷幾次
python3 code6.py
python3 code7-2.py

## 7-3 ##
更改 /etc/tor/torrc 內的值增加下列兩行

    HiddenServiceDir /path/to/my/hw/folder/7-3/
    HiddenServicePort 7122 127.0.0.1:8080

接著照順序在兩個 terminal 跑

python3 code7-3_server.py
python3 code7-3_connect.py

在 server 側輸入 CAPTCHA 即可完成
