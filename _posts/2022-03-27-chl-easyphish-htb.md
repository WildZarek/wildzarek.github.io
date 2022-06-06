---
layout: post
title: Easy Phish (Reto) - WriteUp
author: WildZarek
permalink: /htb/challenges/osint/easyphish
excerpt: "Reto OSINT de HackTheBox en el que aprendemos sobre DMARC y registros DNS."
description: "Reto OSINT de HackTheBox en el que aprendemos sobre DMARC y registros DNS."
date: 2022-03-27
header:
  teaser: /assets/images/hackthebox/challenges/osint/easyphish/pwned_date.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Challenges, OSINT]
tags: [DNS, DMARC, dig-command, Phishing]
---

# Fecha de Resolución

<p align="center">
  <a href="https://www.hackthebox.com/achievement/challenge/18979/79">
    <img src="/assets/images/hackthebox/challenges/osint/easyphish/pwned_date.png">
  </a>
</p>

Saludos pentesters, en esta ocasión vamos a resolver un desafío (cortito) de HackTheBox.

# Easy Phish

Se trata de un desafío **`OSINT`** de nivel fácil. La descripción nos indica lo siguente:

> Customers of secure-startup.com have been recieving some very convincing phishing emails, can you figure out why?

Lo primero es comprobar si existe este dominio lanzando una traza **`ICMP`**

```console
p3ntest1ng:~$ ping -c 1 secure-startup.com
PING secure-startup.com (34.102.136.180) 56(84) bytes of data.
64 bytes from 180.136.102.34.bc.googleusercontent.com (34.102.136.180): icmp_seq=1 ttl=119 time=22.9 ms

--- secure-startup.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 22.892/22.892/22.892/0.000 ms
```

Parece que el dominio existe, vamos a echarle un vistazo en nuestro navegador.

![Easy Phish Web](/assets/images/hackthebox/challenges/osint/easyphish/domain.png)

Se trata de un [dominio aparcado](https://neoattack.com/neowiki/parking-de-dominios/) en **GoDaddy.com**

Volviendo a la descripción del reto, nos dice que los clientes del supuesto sitio web han estado recibiendo correo electrónico con phishing.
Realizando una búsqueda rápida en google, encuentro este resultado:

![Easy Phish DMARC](/assets/images/hackthebox/challenges/osint/easyphish/dmarc.png)

**[¿Qué es DMARC?](https://www.redeszone.net/tutoriales/seguridad/que-es-dmarc-seguridad-correo/)**

> **`DMARC`** son las siglas de **Domain-based Message Authentication, Reporting and Conformance**. 
> En español lo podríamos traducir como _Autenticación de mensajes, informes y conformidad basada en dominios_.
> Es un mecanismo muy útil e importante para el correo electrónico ya que permite la autenticación.

En el primer enlace que encontramos sobre cómo proteger el dominio ante estos ataques nos explican cómo se crea este registro:

> ...se copia como registro TXT con el subdominio _dmarc en la zona de dominio del nombre de servidor.

Sabiendo esto, podemos hacer una consulta de los registros DNS del dominio y el subdominio indicado.

```console
p3ntest1ng:~$ dig TXT secure-startup.com _dmarc.secure-startup.com
```

![Easy Phish DNS](/assets/images/hackthebox/challenges/osint/easyphish/dns.png)

## Solución

**`HTB{RIP_SPF_Always_2nd_F1ddl3_2_DMARC}`**

### ¡Gracias por leer hasta el final!

Este reto me ha resultado entretenido por la parte de investigación ya que no conocía DMARC y siempre viene bien aprender algo nuevo.

#### Nos vemos en un próximo. ¡Feliz hacking! ☠