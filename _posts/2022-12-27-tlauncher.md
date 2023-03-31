---
layout: post
title: Analizando TLauncher
author: WildZarek
permalink: /blog/tlauncher
excerpt: "Analizamos el instalador de TLauncher para descubrir si realmente es un software malicioso. Los resultados son más que evidentes y nos deja claro que este software no es de fiar."
description: "Analizamos el instalador de TLauncher para descubrir si realmente es un software malicioso. Los resultados son más que evidentes y nos deja claro que este software no es de fiar."
date: 2022-12-27
header:
  teaser: /assets/images/blog/tlauncher/tlauncher.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [Software, Analisis, Malware, Spyware]
tags: [AnyRun, Triage, VirusTotal]
---

<p align="center"><img src="/assets/images/blog/tlauncher/tlauncher.png"></p>

Antes de nada, me gustaría desearos a todos una feliz Navidad y un próspero año nuevo.
<br>
Sé que llevo tiempo sin crear contenido, pero en 2023 prometo volver a escribir WriteUps.

Dicho esto, vamos al lío con lo que nos interesa en el día de hoy...

## Introducción

Mucho se ha hablado estos días sobre **TLauncher**, el famoso lanzador multiversiones de **Minecraft**.
Desde hace mes y medio se rumoreaba que dicho software escondía un terrible secreto...

Aunque las sospechas comenzaron mucho antes, hace unos 10 meses en Reddit ya se comenzó a cuestionar la fiabilidad de TLauncher.
Y a raíz de todo ello han surgido diferentes análisis, dando como resultado lo que ya se sospechaba tiempo atrás.

**Sí, ¡TLauncher contiene malware y spyware!**

Afirmar esto sin pruebas sería algo estúpido, por ello voy a ir explicando los resultados de las mismas, 
al mismo tiempo que analizamos cada acción realizada por el instalador oficial de TLauncher.

## Análisis de TLauncher

Para analizar el instalador de **TLauncher** se ha procedido a instalar la versión más reciente en un entorno controlado,
gracias a esto se puede comprobar de forma segura qué es lo que hace dicho software a la hora de instalarlo en nuestro equipo.

Os dejo el primer análisis realizado en [Triage](https://tria.ge/): [https://tria.ge/221227-yx4dmsbc8z/behavioral1](https://tria.ge/221227-yx4dmsbc8z/behavioral1)
<br>
Aunque vamos a centrarnos en el segundo análisis realizado en [AnyRun](https://app.any.run/): [https://app.any.run/tasks/458bd25d-e4e7-43b2-9ebd-f051a8ed24ab/](https://app.any.run/tasks/458bd25d-e4e7-43b2-9ebd-f051a8ed24ab/)

Primero vamos a recopilar los resultados y posteriormente iremos explicando lo más relevante.

![InfoBinario](/assets/images/blog/tlauncher/tlauncher_pup.png)

A continuación, la larga lista de indicadores de comportamiento (IOC's) que lo delatan como un programa malicioso basándonos en la **`MITRE ATT&CK™ MATRIX`**
<br>
Para quien no sepa qué es esto de Mitre, se trata de una base global de conocimiento del comportamiento basado en técnicas de ataque observadas en amenazas reales.

![InfoBinario](/assets/images/blog/tlauncher/tlauncher_pup0.png)
![InfoBinario](/assets/images/blog/tlauncher/tlauncher_pup00.png)

Como vemos en la primera imagen, estamos analizando la última versión, y el resultado global es que realiza ciertas acciones maliciosas,
por lo cual el binario queda marcado como potencialmente peligroso. Veamos en qué consisten estas acciones paso por paso.

![Instalador](/assets/images/blog/tlauncher/tlauncher0.png)

Hasta aquí todo normal, hemos ejecutado el instalador y aún no ha sucedido nada extraño. Sigamos...

![Instalador](/assets/images/blog/tlauncher/tlauncher1.png)

En esta nueva imagen, vemos que el instalador comienza a descargar y depositar en una carpeta temporal de nuestro sistema varios archivos,
entre ellos el binario **`irsetup.exe`**, todo esto sucede aunque no hagas clic en el botón "Continue".
La descarga del archivo ejecutable se hace desde los servidores de TLauncher.
Una vez se ejecuta, inmediatamente hace una petición GET a un servidor para descargarse otro binario llamado **`TLauncher-2.871.exe`**
<br>
Lo que parece indicar que sobreescribe al binario original por uno infectado con malware.

¿Pero a qué servidor hace la petición?
<br>
La petición se lanza contra el servidor **advancedrepository.com**, un dominio registrado en 2019 y que aparentemente no contiene nada.
Por no hablar de lo raro que resulta que se descarguen archivos desde un servidor distinto al de TLauncher. Lo cual ocurre en repetidas ocasiones.

![Instalador](/assets/images/blog/tlauncher/tlauncher1_1.png)

Veamos si esta página web contiene algo interesante...

```console
wildzarek@p3ntest1ng:~$ curl -s -X GET 'https://advancedrepository.com'
<!--
Damnant quod non intellegunt
-->
```

Vacía. El código fuente contiene un comentario que reza una frase en latín, que traducida (por el traductor de Google) significa "Condenan lo que no entienden".
Yo no sé latín y no sé hasta que punto es de fiar la traducción, pero es una frase curiosa y enigmática.

¿Y qué hace este binario?
<br>
Pues bien, he pasado este archivo por [VirusTotal](https://www.virustotal.com/) y aunque a priori no es detectado como malware por ningún antivirus,
si nos fijamos en la tabla Mitre vemos que este binario hace cosas muy extrañas y peligrosas. Os dejo el resultado del análisis completo [AQUÍ](https://www.virustotal.com/gui/file/765cab48564743844b057e21eab768d5d84194a635b09d02d9d2909f632f5714/detection)

Vamos a detallar algunos de los comportamientos sospechosos del binario:

![PUP](/assets/images/blog/tlauncher/tlauncher_pup1.png)
![PUP](/assets/images/blog/tlauncher/tlauncher_pup2.png)
![PUP](/assets/images/blog/tlauncher/tlauncher_pup3.png)
![PUP](/assets/images/blog/tlauncher/tlauncher_pup4.png)

Como vemos en las imágenes, este archivo realiza una serie de acciones bastantes sospechosas y peligrosas que ponen en jaque la seguridad de nuestro sistema.

Sigamos con el análisis...

![Instalador](/assets/images/blog/tlauncher/tlauncher2.png)

En este punto, el programa continúa con la descarga de archivos, uno de ellos es un DLL relacionado con el lenguaje de programación **Lua**,
aunque desactualizado, pues la versión más reciente es la 5.4. Esto podría ser normal dado que muchos de los mods para Minecraft usan este lenguaje en parte de su código, aunque generalmente están escritos en **Java**.

Lo siguiente que vemos en el punto 2 es que se crea un proceso COM++ embebido, algo común en muchísimas aplicaciones,
ya que esto se utiliza con el propósito de ejecutar objetos COM aparte de los procesos originales que los solicitan.
Para simplificarlo bastante más, digamos que es necesario para utilizar paralelismo (ejecutar dos acciones al mismo tiempo de forma independiente).
<br>
No vamos a entrar en detalle respecto a esto, pues es algo más técnico de explicar. Lo que debemos tener en cuenta es que **`DllHost.exe`**,
un binario legítimo de Windows, es utilizado a menudo por diversos tipos de malware, llegando a ocupar el 100% de uso tanto de la RAM como de la CPU.

Sigamos...

![Instalador](/assets/images/blog/tlauncher/tlauncher3.png)

Le damos a "Continue" y se nos invita a instalar el navegador **Opera**, algo que podría ser normal,
sin embargo este tipo de propuestas suelen considerarse como Adware, ya que por lo general el usuario no quiere instalar software adicional.
Más adelante veremos algo relacionado con esto.

En las alertas de arriba a la derecha vemos que nos descarga dos archivos con la extensión **`.LMD`**

¿Qué es la extensión [LMD](https://www.fileviewpro.com/es/file-extension-lmd)?

> Es un tipo de archivo **Abbyy Finereader Sprint File** creado para el software ABBYY FineReader desarrollado por ABBYY.
> Estos archivos son muy populares entre los usuarios de **China**.

Un poco raro...uno de ellos se llama **`Wow64.lmd`** y podríamos pensar que tiene algo que ver con el binario legítimo de Windows **`wow64.exe`** pero no tengo pruebas de ello.

¿Qué es WOW64 en Windows?

> WOW64 es un subsistema de Microsoft Windows capaz de ejecutar aplicaciones de 32 bit y que se incluye en todas las versiones de 64 bit de Windows.
> WOW64 se encarga de todas las diferencias en las versiones 32 y 64 bit de Windows, especialmente las que implican cambios estructurales en el propio Windows.

Sin duda se trata de un binario crítico de Windows. Pero sigamos con el análisis...

![Instalador](/assets/images/blog/tlauncher/tlauncher4.png)

Aquí termina la instalación y como vemos en la imagen, lo primero que hace es ejecutar el binario **`TLauncher-2.871.exe`** descargado previamente,
el cual vimos que tiene una serie de comportamientos de dudosa fiabilidad. Llegados a este punto ya estaríamos infectados.

Veamos algunas de las peticiones HTTP que se han realizado durante el proceso de instalación:

![Peticiones](/assets/images/blog/tlauncher/tlauncher_requests.png)

Comprobemos qué nos devuelve la primera petición:

```console
wildzarek@p3ntest1ng:~$ curl -s -X GET 'https://dl2.tlauncher.org/check_latest_tl.php?optime=0'
2.871
27460
true
MSTL
true
ES
154127
```

Parece que se hace una comprobación de algunos datos, entre ellos la versión del binario y otros que no sé qué son exactamente, finalmente se comprueba nuestro idioma.
Es la curiosidad la que me lleva a comprobar estas cosas, con la esperanza de descubrir algo interesante.

En otra de las peticiones encontramos una lista de servidores de Minecraft:

```console
wildzarek@p3ntest1ng:~$ curl -s -X GET 'http://repo.tlauncher.org/update/downloads/configs/inner_servers.json'
{
  "newServers":  [
    {
      "name": "VimeMC.net",
      "hideAddress": true,
      "acceptTextures": 1,
      "address": "mc.vimemc.net:25565",
      "minVersion": "1.8",
      "recoveryServerTime": 12,
      "maxRemovingCountServer": 2,
      "ignoreVersions": [],
      "includeVersions": [],
	  "locales":["ru_RU","uk_UA"]
    }
  ],
  "removedServers":[
    "prinemc.ru:25565",
    "prinemc.ru",
    "play.hypemc.su:25565",
    "play.hypemc.su",
    "mc.hypemc.su:25565",
    "mc.hypemc.su",
    "purplecraft.ru:25565",
    "purplecraft.ru",
    "mc.purplecraft.ru:25565",
    "mc.purplecraft.ru",
    "mc.hydramc.me:25565",
    "mc.hydramc.me",
    "mc.eljonik.ru:25565",
    "mc.eljonik.ru",
    "play.eljonik.ru:25565",
    "play.eljonik.ru",
    "mr.dimersive.xyz:25565",
    "mr.dimersive.xyz",
    "mc.FunnyMine.ru:25565",
    "mc.FunnyMine.ru",
    "mc.livemine.ru:25565",
    "mc.livemine.ru",
    "play.spaceside.ru:25565",
    "play.spaceside.ru",
    "strixmine.ru:25565",
    "strixmine.ru",
    "mc.prostocraft.ru:25565",
    "mc.prostocraft.ru",
    "voxmine.ru:25565",
    "voxmine.ru",
    "vrscraft.ru:25565",
    "vrscraft.ru",
    "mc.vrscraft.ru:25565",
    "mc.vrscraft.ru",
    "146.59.181.68:25584",
    "mc.fatemine.ru:25565",
    "mc.fatemine.ru",
    "mc.QMine.ru:25565",
    "mc.QMine.ru",
    "mc.avastmine.ru:25565",
    "mc.avastmine.ru",
    "mc.mac-craft.ru:25565",
    "mc.mac-craft.ru",
    "pepsimc.ru:25565",
    "pepsimc.ru",
    "upgo.su:25565",
    "upgo.su",
    "mc.stillmine.ru:25565",
    "mc.stillmine.ru",
    "bcmc.xyz:25565",
    "bcmc.xyz",
    "play.boomc.ru:25565",
    "play.boomc.ru",
    "mc.boomc.ru:25565",
    "mc.boomc.ru",
    "play.boomcraft.ru:25565",
    "play.boomcraft.ru",
    "mc.boomcraft.ru:25565",
    "mc.boomcraft.ru",
    "kswrd.pro:25565",
    "kswrd.pro",
    "mc.game-nix.ru:25565",
    "mc.game-nix.ru",
    "luckyc.ru:25565",
    "luckyc.ru",
    "54.37.201.199:25565",
    "54.37.201.199",
    "51.75.44.85:25565",
    "51.75.44.85",
    "mdest.ru:25565",
    "mdest.ru",
    "mc.forsemc.ru:25565",
    "mc.forsemc.ru",
    "mc.magicmc.ru:25565",
    "mc.magicmc.ru",
    "play.exploitmc.xyz:25565",
    "play.exploitmc.xyz",
    "play.skymc.xyz:25565",
    "play.skymc.xyz",
    "mc.emeraldland.ru:25565",
    "mc.emeraldland.ru",
    "mc.firegrief.ru:25565",
    "mc.firegrief.ru",
    "mc.fausmc.ru:25565",
    "mc.fausmc.ru",
    "mc.blockmc.ru:25565",
    "mc.blockmc.ru",
    "mc.gamedex.ru:25565",
    "mc.gamedex.ru",
    "zigamc.tk:25565",
    "zigamc.tk",
    "go.zigadon.ru:25565",
    "go.zigadon.ru",
    "mc.slymine.ru:25565",
    "mc.slymine.ru",
    "mc.dexcloud.ru:25565",
    "mc.dexcloud.ru",
    "go.vaskacraft.ru:25565",
    "go.vaskacraft.ru",
    "zigamc.ru:25565",
    "zigamc.ru",
    "mine-cld.ru:25565",
    "mine-cld.ru",
    "mc.minedrugs.ru:25565",
    "mc.minedrugs.ru",
    "play.cubeway.ru:25565",
    "play.cubeway.ru",
    "mc.mased-world.ru:25565",
    "mc.mased-world.ru",
    "mc.vimemc.su:25565",
    "mc.vimemc.su",
    "mc.mc-w.ru:25565",
    "mc.mc-w.ru",
    "m.mgw.su:25565",
    "m.mgw.su",
    "play.mgw.su:25565",
    "play.mgw.su",
    "mc.mgw.su:25565",
    "mc.mgw.su",
    "mc.gws.su:25565",
    "mc.gws.su",
    "mc.bladestorm.ru:25565",
    "mc.bladestorm.ru",
    "mc.lastmine.ru:25565",
    "mc.lastmine.ru",
    "play.imperial-mc.ru:25565",
    "play.imperial-mc.ru",
    "mc.vormir.ru:25565",
    "mc.vormir.ru",
    "vormir.ru:25565",
    "vormir.ru",
    "mc.flexland.ru:25565",
    "mc.flexland.ru",
    "freshmc.su:25565",
    "freshmc.su",
    "play.FreshMC.su:25565",
    "play.FreshMC.su",
    "go.cherryland.su:25565",
    "go.cherryland.su",
    "mc.cherryland.su:25565",
    "mc.cherryland.su",
    "gta-mc.su:25565",
    "gta-mc.su",
    "mc.bigcraft.su:25565",
    "mc.bigcraft.su",
    "play.enot.io:25565",
    "play.enot.io",
    "enot.io:25565",
    "enot.io",
    "mc.daycrafts.ru:25565",
    "mc.daycrafts.ru",
    "daycrafts.ru:25565",
    "daycrafts.ru",
    "somego.pro:25565",
    "somego.pro",
    "brillgo.pro:25565",
    "brillgo.pro",
    "mc.firecerv.ru:25565",
    "firecerv.ru:25565",
    "mc.firecerv.ru",
    "firecerv.ru",
    "mc.funnysc.ru:25565",
    "funnysc.ru:25565",
    "mc.funnysc.ru",
    "funnysc.ru",
    "mc.sminer.ru:25565",
    "mc.sminer.ru",
    "join.sminer.ru:25565",
    "join.sminer.ru",
    "play.sminer.ru:25565",
    "play.sminer.ru",
    "gravitymc.ru:25565",
    "gravitymc.ru",
    "mcbig.ru:25565",
    "mcbig.ru",
    "mc.plend.ru:25565",
    "mc.plend.ru",
    "mc.minedex.io",
    "mc.minedex.io:25565",
    "play.minedex.io",
    "play.minedex.io:25565"
  ],
  "clientChangedAddress": [
    {
      "oldAddress": "masedworld.ru",
      "newAddress": "mc.masedworld.net"
    },
    {
      "oldAddress": "masedworld.ru:25565",
      "newAddress": "mc.masedworld.net"
    },
    {
      "oldAddress": "mc.masedworld.ru",
      "newAddress": "mc.masedworld.net"
    },
    {
      "oldAddress": "mc.masedworld.ru:25565",
      "newAddress": "mc.masedworld.net"
    },
    {
      "oldAddress": "skycave.ru",
      "newAddress": "mc.skycave.pro"
    },
    {
      "oldAddress": "skycave.ru:25565",
      "newAddress": "mc.skycave.pro"
    },
    {
      "oldAddress": "mc.skycave.ru",
      "newAddress": "mc.skycave.pro"
    },
    {
      "oldAddress": "mc.skycave.ru:25565",
      "newAddress": "mc.skycave.pro"
    }
  ]
}
```

Todos estos servidores son rusos, aunque están en el apartado 'removedServers'...Otra curiosidad.
<br>
Otra de las peticiones se realiza contra el servidor de **`Mojang`** para comprobar las versiones existentes:

```console
wildzarek@p3ntest1ng:~$ curl -s -X GET 'https://launchermeta.mojang.com/mc/game/version_manifest.json' | jq

{
  "latest": {
    "release": "1.19.3",
    "snapshot": "1.19.3"
  },
  "versions": [
    {
      "id": "1.19.3",
      "type": "release",
      "url": "https://piston-meta.mojang.com/v1/packages/6607feafdb2f96baad9314f207277730421a8e76/1.19.3.json",
      "time": "2022-12-07T08:58:43+00:00",
      "releaseTime": "2022-12-07T08:17:18+00:00"
    },
    {
      "id": "1.19.3-rc3",
      "type": "snapshot",
      "url": "https://piston-meta.mojang.com/v1/packages/3cee07d5dbdf81832a05613987fefdecae2eb37b/1.19.3-rc3.json",
      "time": "2022-12-07T08:58:43+00:00",
      "releaseTime": "2022-12-06T10:24:01+00:00"
    },
    {
      "id": "1.19.3-rc2",
      "type": "snapshot",
      "url": "https://piston-meta.mojang.com/v1/packages/1444fdf3b0e4c4891cb6d13b462ac2c72fa44afd/1.19.3-rc2.json",
      "time": "2022-12-07T08:58:43+00:00",
      "releaseTime": "2022-12-05T13:21:34+00:00"
    },
    {
      "id": "1.19.3-rc1",
      "type": "snapshot",
      "url": "https://piston-meta.mojang.com/v1/packages/d0ef907403bc461b20c2a1586f660be973622449/1.19.3-rc1.json",
      "time": "2022-12-07T08:58:43+00:00",
      "releaseTime": "2022-12-01T13:45:18+00:00"
    },
---[SNIP]---
```

He recortado el output por ser muy largo y de poco interés, pero como curiosidad ahí está.
Y otra más de las peticiones, que no tiene mucha utilidad más allá de un "control" de respuesta por parte del servidor:

```console
wldzarek@p3ntest1ng:~$ curl -s -X GET 'https://dl2.fastrepo.org/not_remove_test_file.txt'
test
```

Bueno, sigamos con peticiones más interesantes...

Si nos fijamos, hay varias peticiones de descarga de archivos que no están en los servidores de TLauncher,
estas peticiones apuntan al servidor **advancedrepository.com** mencionado anteriormente.
En una de ellas se descarga un archivo comprimido relacionado con Java 8 de nombre **`jre-8u281-windows-x64.zip`** directamente desde los servidores de TLauncher.

Java es de pago y esto podría entenderse como que te están facilitando una versión pirata de Java, pero existen alternativas que podrían haber utilizado,
sin embargo han usado una versión de Java que no sabemos de dónde procede.
Aunque como veremos en la próxima imagen, este Java hace cosas raras. En el análisis del instalador se detectó lo siguiente:

![JavaThreats](/assets/images/blog/tlauncher/tlauncher_java_threats.png)

Hay otra petición interesante en la cual vemos que se devuelve un JSON string, que contiene las URL's de descarga del navegador **Opera** y **Yandex**,
esto es en base al idioma del usuario, ya que dependiendo de ello te ofrece instalar uno u otro.

```console
wildzarek@p3ntest1ng:~$ curl -s -X GET 'http://advancedrepository.com/update/lch/update_2.0.json?version=2.871&client=14677fce-744e-4e1e-bbd2-8d7686310c9f'
---[SNIP]---
  "jarLinks": [
    "http://repo.tlauncher.org/update/lch/TLauncher-2.86.jar",
    "http://dl2.fastrepo.org/client/TLauncher-2.86.jar"
  ],
  "exeLinks": [
    "http://repo.tlauncher.org/update/lch/TLauncher-2.86.exe",
    "http://dl2.fastrepo.org/client/TLauncher-2.86.exe"
  ],
  "mandatory": false,

  "updaterView": 2,
  "updaterLaterInstall":false,
  "offerDelay":30,
  "offerEmptyCheckboxDelay":2,
  "offers": [
    {
      "offer":"yabro",
      "installer": "https://download.yandex.ru/yandex-pack/downloader/downloader.exe",
      "args": {
        "": "--partner 27460 --noaction 1",
        "checkbox1": "--partner 27460 --distr /quiet /msicl \"YABROWSER=y ILIGHT=1 VID=4\"",
        "checkbox2": "--partner 27460 --distr /quiet /msicl \"YAHOMEPAGE=y YAQSEARCH=y ILIGHT=1 VID=4\"",
        "checkbox1+checkbox2": "--partner 27460 --distr /quiet /msicl \"YABROWSER=y YAHOMEPAGE=y YAQSEARCH=y ILIGHT=1 VID=4\""
      },
      "startCheckboxSouth": 225,
      "checkBoxes": [
        {
          "name": "checkbox1",
          "active": true,
          "texts": {
            "ru_RU": "<html>Загрузить и установить Яндекс.Браузер</html>"
          }
        },
        {
          "name": "checkbox2",
          "active": true,
          "texts": {
            "ru_RU": "<html>Загрузить и установить настройки быстрого <br>доступа к поиску и сервисам Яндекса</html>"
          }
        }
      ],
---[SNIP]---
      {
      "offer":"operabro",
      "installer": "http://repo.tlauncher.org/uploads/installer-2.exe",
      "args": {
        "": "--test 1",
        "checkbox1": "--test 1"
      },
      "startCheckboxSouth": 225,
      "checkBoxes": [
        {
          "name": "checkbox1",
          "active": true,
          "texts": {
			"uk_UA": "<html>Завантажте та встановіть браузер Opera</html>",
			"en_US": "<html>Download and install Opera browser</html>",
			"de_DE": "<html>Downloaden und installieren Sie den Opera-Browser</html>",
			"es_ES": "<html>Descargar e instalar el navegador Opera</html>",
			"fr_FR": "<html>Téléchargez et installez le navigateur Opera</html>",
			"it_IT": "<html>Scaricare e installare il browser Opera</html>",
            "pl_PL": "<html>Pobierz i zainstaluj przeglądarkę Opera</html>",
			"pt_PT": "<html>Descarregar e instalar o navegador Opera</html>",
			"ro_RO": "<html>Descărcati si instalati browserul Opera</html>",
			"zh_CN": "<html>下载和安装Opera浏览器</html>"
          }
        }
      ],
```

¿Os habéis fijado en un detalle?:
<br>
Si eres ruso te ofrecen instalar Yandex y lo descargan de la web oficial (o eso parece),
<br>
al resto nos ofrecen Opera y lo descargan del servidor de TLauncher con nombre **`installer-2.exe`**


Si no existiesen rumores sobre que este malware lo ha orquestado un grupo de ciberdelincuentes
rusos que ha engañado a todo el mundo, cada detalle que encuentro parece confirmar que todo apunta en efecto a Rusia.

Por desgracia no he podido descargarme el binario del supuesto Opera para analizarlo:

```console
wildzarek@p3ntest1ng:~$ wget 'http://repo.tlauncher.org/uploads/installer-2.exe'

--2022-12-27 22:38:20--  http://repo.tlauncher.org/uploads/installer-2.exe
Resolviendo repo.tlauncher.org (repo.tlauncher.org)... 104.20.234.70, 104.20.235.70, 2606:4700:10::6814:eb46, ...
Conectando con repo.tlauncher.org (repo.tlauncher.org)[104.20.234.70]:80... conectado.
Petición HTTP enviada, esperando respuesta... 404 Not Found
2022-12-27 22:38:20 ERROR 404: Not Found.
```

Siguiendo con las peticiones, encontramos también que se envían dos peticiones a **https://stat.fastrepo.org/save/run/tlauncher/unique/month**,
aunque no sabemos qué tipo de información se ha enviado a dicha URL. Puntualizar que estas peticiones las hace el binario **`javaw.exe`**

# Conclusiones

Con estos análisis y pruebas, creo que ha quedado demostrado que **`TLauncher`** es un software potencialmente peligroso,
al ser catalogado como malware; Especialmente considerado spyware. Sin duda los resultados obtenidos nos alertan que
deberíamos desinstalarlo cuanto antes de nuestro sistema operativo. El problema es que como hemos visto, deshacernos del malware no va a ser tan simple
como desinstalar TLauncher, ya que hemos visto que utiliza técnicas de persistencia muy avanzadas. Esto significa que aunque elimines TLauncher,
el malware seguirá en el sistema y por desgracia librarnos por completo no es algo que podamos hacer con dos clics.

# Recomendaciones

Debido a la persistencia generada por el malware, lo ideal es formatear el disco duro.
De este modo podremos comenzar con una nueva instalación de Windows completamente limpia.
Para ello es recomendable que previamente hagamos una copia de seguridad de todos nuestros datos y archivos personales.

Si quieres jugar a Minecraft, deberías adquirir el juego oficial comprándolo en Microsoft Store o tiendas autorizadas,
aunque si esto no es posible por cualquier motivo, existen otros lanzadores de Minecraft como puede ser **`MultiMC`**,
que también es gratuito y además de código abierto. Un buen punto a favor de este lanzador,
ya que la comunidad puede analizar el código fuente del software en cualquier momento.

Sin embargo, este tipo de lanzadores infringen los derechos de autor al utilizar un software privado como lo es Minecraft.
Utilizarlos queda bajo tu entera responsabilidad...

Bueno, eso ha sido todo por esta vez. Espero haber arrojado un poco de luz sobre este asunto.

### ¡Gracias por leer hasta el final!

#### Nos vemos en un próximo. ¡Feliz hacking! ☠