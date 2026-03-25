import requests
import re
import os
import sys
import time
import random
import urllib3
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 忽略安全检查
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class KingoProber:
    """
    真正的青果系统路径嗅探器：仅适配传统 ASP.NET 版本
    """
    def _minimal_cas_probe(self, html):
        """仅提取学校代码，不进行深度适配"""
        code = "NOT_FOUND"
        m = re.search(r"var\s+schoolcode\s*=\s*['\"](\d+)['\"]", html)
        if m: code = m.group(1)
        print(f'SCHOOL_CODE = "{code}"')
        print(f'SCHOOL_HOST = "{self.domain_root}"')
        print(f'JWWEB_BASE = "{self.app_root}"')

    def __init__(self, raw_url):
        self.raw_url = raw_url
        self.session = requests.Session()
        
        # 配置重试策略
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.ua_list = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1"
        ]
        # 初始 Header 伪装成从百度搜索点击进入
        self.base_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }
        
        self.domain_root = ""
        self.app_root = ""
        self.config = {}
        self.last_success_url = "https://www.baidu.com/link?url=search_engine_entry"

    def _request(self, method, url, **kwargs):
        # 智能随机延迟
        time.sleep(random.uniform(0.8, 2.5))
        
        headers = self.base_headers.copy()
        headers["User-Agent"] = random.choice(self.ua_list)
        headers["Referer"] = self.last_success_url or url
        
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        try:
            res = self.session.request(method, url, headers=headers, timeout=kwargs.pop("timeout", 10), verify=False, **kwargs)
            if res.status_code in [200, 302]:
                self.last_success_url = url
            elif res.status_code in [403, 406, 418]:
                print(f" [!] 警告: 状态码 {res.status_code}，疑似被风控，强制休眠...")
                time.sleep(random.uniform(5.0, 10.0))
            return res
        except Exception:
            time.sleep(2.0)
            return None

    def _probe_path(self, path):
        base = self.app_root.rstrip('/')
        url = base + "/" + path.lstrip('/')
        res = self._request("HEAD", url, allow_redirects=False, timeout=3)
        if res and res.status_code == 405:
            res = self._request("GET", url, allow_redirects=False, timeout=3)
        if res and res.status_code not in (404, 500):
            return path
        return None

    def _to_relative_path(self, full_url):
        clean_url = full_url.split('?', 1)[0]
        app_root = self.app_root.rstrip('/')
        domain_root = self.domain_root.rstrip('/')
        if clean_url.startswith(app_root + "/"):
            rel = clean_url[len(app_root):]
        elif clean_url.startswith(domain_root + "/"):
            rel = clean_url[len(domain_root):]
        else:
            rel = urlparse(clean_url).path or clean_url
        return rel if rel.startswith('/') else "/" + rel

    def _analyze_structure(self, url):
        parsed = urlparse(url)
        domain_root = f"{parsed.scheme}://{parsed.netloc}"
        
        query_params = re.findall(r'[?&](?:service|url|redirect)=([^&]+)', url)
        target_path_url = url
        if query_params:
            from urllib.parse import unquote
            service_url = unquote(query_params[0])
            if 'http' in service_url:
                s_parsed = urlparse(service_url)
                domain_root = f"{s_parsed.scheme}://{s_parsed.netloc}"
                target_path_url = service_url

        p_parsed = urlparse(target_path_url)
        path_parts = p_parsed.path.strip('/').split('/')
        valid_parts = []
        for p in path_parts:
            if not p or '.' in p or p.endswith('.action') or any(k in p.lower() for k in ['login', 'auth', 'cas']):
                break
            valid_parts.append(p)
        
        app_path = "/" + "/".join(valid_parts) if valid_parts else ""
        app_root = domain_root + app_path
        return domain_root, app_root

    def probe(self):
        print(f"[*] 解析目标: {self.raw_url}")
        self.domain_root, self.app_root = self._analyze_structure(self.raw_url)
        print(f"[*] 域名核心: {self.domain_root}")
        print(f"[*] 应用基础: {self.app_root}")
        
        possible_logins = [self.raw_url]
        bases = [self.app_root.rstrip('/')]
        if self.app_root == self.domain_root:
            bases.extend([f"{self.domain_root}/jwweb", f"{self.domain_root}/jwgl", f"{self.domain_root}/jwxt", f"{self.domain_root}/jsxsd"])
        
        for b in bases:
            possible_logins.extend([
                f"{b}/Default.aspx",
                f"{b}/_data/home_login.aspx",
                f"{b}/cas/login.action"
            ])
        
        seen = set()
        possible_logins = [x for x in possible_logins if not (x in seen or seen.add(x))]
        
        target_html = ""
        login_url = ""
        system_type = "Kingo (青果)"

        for url in possible_logins:
            try:
                print(f"[*] 正在探测: {url}")
                res = self._request("GET", url, allow_redirects=True)
                if not res or res.status_code != 200: continue
            except Exception: continue

            html = res.text
            if "txt_asmc" in html or "chkpwd" in html or "schoolcode" in html.lower():
                target_html, login_url = html, res.url
                break
            if "zftal" in html or "jwglxt" in html or "正方软件" in html:
                system_type = "ZF (正方)"
                target_html, login_url = html, res.url
                break
            if any(k in html.lower() for k in ["vue.js", "element-ui", "chunk-", "wisedu", "authserver", "cpdaily"]):
                system_type = "Modern / Wisedu"
                target_html, login_url = html, res.url
                break

        if not target_html:
            print("\n[!] 警告: 无法探测到已知的青果系统特征。")
            return

        print(f"[+] 识别到系统类型: {system_type}")
        if system_type != "Kingo (青果)":
            print(f"\n[!] 本项目暂不支持 {system_type} 系统。")
            return

        if "/cas/" in login_url or "yzmbt" in target_html:
            print("\n" + "!"*75)
            print("探测到该校使用的是【2018+ 现代版 (CAS 架构) 青果系统】。")
            print("由于其加密逻辑过于复杂且动态，本脚本暂未适配。")
            print("请参考 CAS_ADAPTATION_GUIDE.md 获取逆向干货并提交 PR。")
            print("!"*75)
            self._minimal_cas_probe(target_html)
            return

        # 1. SCHOOL_CODE 多重正则搜索
        self.config["SCHOOL_CODE"] = "NOT_FOUND"
        patterns = [
            r"var\s+schoolcode\s*=\s*['\"](\d+)['\"]",
            r"(?:chkpwd|chkyzm|checkYzm|md5).*?['\"](\d+)['\"]",
            r"schoolcode\s*[:=]\s*['\"](\d+)['\"]",
            r"txt_asmcdefsddsd.*?['\"](\d+)['\"]",
            r"val\(['\"](\d+)['\"]\)",
            r"value=[\"'](\d+)[\"'][^>]*id=[\"']schoolcode[\"']",
            r"id=[\"']schoolcode[\"'][^>]*value=[\"'](\d+)[\"']"
        ]
        for pat in patterns:
            m = re.search(pat, target_html, re.IGNORECASE)
            if m:
                self.config["SCHOOL_CODE"] = m.group(1)
                break

        # 2. 字段模糊打分系统 (Fuzzy Probing)
        soup = BeautifulSoup(target_html, 'html.parser')
        field_keys = ["LOGIN_FIELD_VIEWSTATE", "LOGIN_FIELD_EVENTVALIDATION", 
                      "LOGIN_FIELD_PCINFO", "LOGIN_FIELD_USERNAME", 
                      "LOGIN_FIELD_PASSWORD", "LOGIN_FIELD_USERTYPE"]
        for k in field_keys: self.config[k] = "NOT_FOUND"
        
        # 用户名权重嗅探器
        user_cands = []
        for inp in soup.find_all('input'):
            it = inp.get('type', '').lower()
            name = inp.get('name', '')
            id_v = inp.get('id', '')
            if it == 'hidden' or not name: continue
            
            score = 0
            # 特征点打分
            for feature in ['asmc', 'txt_asmc']: 
                if feature in name.lower() or feature in id_v.lower(): score += 100
            for feature in ['username', 'account', 'userid', 'userzh']: 
                if feature in name.lower() or feature in id_v.lower(): score += 80
            if it == 'text' and ('user' in name.lower() or 'login' in name.lower()): score += 30
            
            if score > 0: user_cands.append((score, name))
            
        if user_cands:
            user_cands.sort(key=lambda x: x[0], reverse=True)
            self.config["LOGIN_FIELD_USERNAME"] = user_cands[0][1]

        # 密码直接定位
        p_el = soup.find('input', {'type': 'password'})
        if p_el: self.config["LOGIN_FIELD_PASSWORD"] = p_el['name']

        # 传统 ASP.NET 隐藏字段识别
        hiddens = {inp.get('name'): inp.get('value') for inp in soup.find_all('input', {'type': 'hidden'}) if inp.get('name')}
        if '__VIEWSTATE' in hiddens: self.config["LOGIN_FIELD_VIEWSTATE"] = "__VIEWSTATE"
        if '__EVENTVALIDATION' in hiddens: self.config["LOGIN_FIELD_EVENTVALIDATION"] = "__EVENTVALIDATION"
        
        # 记录所有非空隐藏字段供用户参考
        self.known_hiddens = [n for n in hiddens.keys() if n and not n.startswith('__')]

        pc_el = soup.find('input', {'name': re.compile(r'pcInfo', re.I)})
        self.config["LOGIN_FIELD_PCINFO"] = pc_el['name'] if pc_el else "pcInfo"
        ut_el = soup.find(['input', 'select'], {'name': re.compile(r'typeName|userType', re.I)})
        self.config["LOGIN_FIELD_USERTYPE"] = ut_el['name'] if ut_el else "typeName"

        self.config["URL_VALIDATE_CODE"] = "NOT_FOUND"
        vc_el = soup.find('img', {'src': re.compile(r'ValidateCode|validate|ashx|yzm|code', re.I)})
        if vc_el and 'themes/kingo/images/validate.png' not in vc_el['src']:
            full_vc = urljoin(login_url, vc_el['src']).split('?')[0]
            self.config["URL_VALIDATE_CODE"] = self._to_relative_path(full_vc)

        print("[*] 正在进行接口存活性嗅探...")
        probe_targets = {
            "URL_DEFAULT": ["/Default.aspx"],
            "URL_LOGIN_HOME": ["/_data/home_login.aspx"],
            "URL_MAIN_FRAME": ["/MAINFRM.aspx"],
            "URL_LOGOUT": ["/sys/Logout.aspx"],
            "URL_MAIN_TOOLS": ["/SYS/Main_tools.aspx"],
            "URL_COURSE_SELECT": ["/wsxk/stu_xszx.aspx"],
            "URL_COURSE_REPORT": ["/wsxk/stu_xszx_rpt.aspx"],
            "URL_CLASS_CHOOSE": ["/wsxk/stu_xszx_chooseskbj.aspx"],
            "URL_WITHDRAW_RESULT": ["/wsxk/stu_txjg_rpt.aspx"]
        }
        final_paths = {k: "NOT_FOUND" for k in probe_targets}
        for key, paths in probe_targets.items():
            for p in paths:
                if self._probe_path(p):
                    final_paths[key] = p
                    break
        self.print_report(final_paths)
        return final_paths

    def print_report(self, paths):
        print("\n" + "="*75)
        print("# 学校基本信息 (提取自传统版)")
        print(f'SCHOOL_CODE = "{self.config.get("SCHOOL_CODE", "NOT_FOUND")}"')
        print(f'SCHOOL_HOST = "{self.domain_root}"')
        print(f'JWWEB_BASE = "{self.app_root}"')
        
        print("\n# 教务系统URL路径")
        keys = ["URL_DEFAULT", "URL_LOGIN_HOME", "URL_VALIDATE_CODE", "URL_MAIN_FRAME", "URL_LOGOUT", "URL_MAIN_TOOLS"]
        for k in keys:
            val = paths.get(k, "NOT_FOUND") if k != "URL_VALIDATE_CODE" else self.config[k]
            print(f'{k} = "{val}"')
            
        print("\n# 选课相关URL路径")
        course_keys = ["URL_COURSE_SELECT", "URL_COURSE_REPORT", "URL_CLASS_CHOOSE", "URL_WITHDRAW_RESULT"]
        for k in course_keys:
            print(f'{k} = "{paths.get(k, "NOT_FOUND")}"')
            
        print("\n# 登录字段名")
        if self.known_hiddens:
            print(f"# 提示: 探测到以下潜在隐藏字段 (若自动识别失败可尝试): {', '.join(self.known_hiddens)}")
            
        field_keys = ["LOGIN_FIELD_VIEWSTATE", "LOGIN_FIELD_EVENTVALIDATION", "LOGIN_FIELD_PCINFO", 
                      "LOGIN_FIELD_USERNAME", "LOGIN_FIELD_PASSWORD", "LOGIN_FIELD_USERTYPE"]
        for k in field_keys:
            print(f'{k} = "{self.config.get(k, "NOT_FOUND")}"')
        print("="*75)

    def verify_config(self, paths):
        if self.config.get("URL_VALIDATE_CODE") in ("", "NOT_FOUND"):
            print(" [-] 跳过验证: 未探测到验证码接口")
            return
        vc_url = self.app_root.rstrip('/') + self.config["URL_VALIDATE_CODE"]
        print(f"[*] 验证验证码接口: {vc_url}")
        res = self._request("GET", vc_url, timeout=5)
        if res and res.status_code == 200 and "image" in res.headers.get("Content-Type", "").lower():
            print(" [+] 验证通过！")
        else:
            print(f" [-] 验证失败: {res.status_code if res else 'None'}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python3 kingo_prober.py <URL> [--verify]")
    else:
        prober = KingoProber(sys.argv[1])
        paths = prober.probe()
        if "--verify" in sys.argv and paths:
            prober.verify_config(paths)
