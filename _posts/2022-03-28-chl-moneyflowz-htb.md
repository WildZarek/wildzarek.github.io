---
layout: post
title: Money Flowz (Reto) - WriteUp
author: WildZarek
permalink: /htb/challenges/osint/money-flowz
excerpt: "Reto OSINT de HackTheBox en el que exploramos el misterioso negocio de un tal Frank, indagando en su Reddit y revisando en la blockchain las transacciones de unas wallets de Ethereum."
description: "Reto OSINT de HackTheBox en el que exploramos el misterioso negocio de un tal Frank, indagando en su Reddit y revisando en la blockchain las transacciones de unas wallets de Ethereum."
date: 2022-03-28
header:
  teaser: /assets/images/hackthebox/challenges/osint/moneyflowz/pwned_date.png
  teaser_home_page: true
  icon: /assets/images/hackthebox/htb_icon_original.png
categories: [HackTheBox, Challenges, OSINT]
tags: [Ethereum]
---

# Fecha de Resolución

<p align="center">
  <a href="https://www.hackthebox.com/achievement/challenge/18979/123">
    <img src="/assets/images/hackthebox/challenges/osint/moneyflowz/pwned_date.png">
  </a>
</p>

Saludos pentesters, en esta ocasión estaremos resolviendo un desafío OSINT de HackTheBox.

# Money Flowz

Se trata de un desafío **`OSINT`** de nivel fácil. La descripción nos indica lo siguente:

> Frank Vitalik is a hustler, can you figure out where the money flows?

Lo primero es buscar en Google quién es este tal Frank.

![Search](/assets/images/hackthebox/challenges/osint/moneyflowz/search1.png)

![Reedit](/assets/images/hackthebox/challenges/osint/moneyflowz/reddit.png)

Viendo su descripción en Reddit, podemos estar seguros de que estamos en el lugar correcto.
Revisando el post principal, no encuentro nada interesante, nos habla de una estafa con tokens ERC20 de Ethereum.
Sin embargo el segundo post, un poco más abajo, nos invita a visitar un enlace que lleva a una página en Steemit.

![Scam Post](/assets/images/hackthebox/challenges/osint/moneyflowz/post.png)

![Scam Post](/assets/images/hackthebox/challenges/osint/moneyflowz/scam.png)

Nuestro amigo Frank parece que quiere estafarnos, nos deja la dirección de su wallet invitandonos a transferir 10x ETH para recibir 20X ETH de vuelta.
Si nos fijamos, vemos un comentario en esta publicación del propio autor en el cual vemos una dirección web: **`ropsten.net`**

Ethereum tiene varias redes, siendo **`mainnet`** la principal. Pero también cuenta con otras redes públicas de prueba,
como son **Goerli**, **Rinkeby**, **Kovan** y **`Ropsten`**

![Search](/assets/images/hackthebox/challenges/osint/moneyflowz/search2.png)

Pongamos la dirección de la wallet que vimos anteriormente en el post en el explorador blockchain para ver sus transacciones.

![Ropstein](/assets/images/hackthebox/challenges/osint/moneyflowz/ropstein1.png)

Hay un total de 123 transacciones, por lo que revisar todas no es viable, pero vamos a buscar las primeras transacciones.

![Ropstein](/assets/images/hackthebox/challenges/osint/moneyflowz/ropstein2.png)

De estas transacciones me interesan las salientes (marcadas con OUT) así que vamos a analizar la primera.

![Ropstein](/assets/images/hackthebox/challenges/osint/moneyflowz/ropstein3.png)

## Solución

Encontramos datos en formato hexadecimal, si le damos al boton **`View Input As`** y elegimos **`UTF-8`** conseguimos la flag de este reto.

![Flag](/assets/images/hackthebox/challenges/osint/moneyflowz/flag.png)

### ¡Gracias por leer hasta el final!

Este desafío me ha resultado algo tedioso de realizar y en mi opinión un poco enrevesado para ser un OSINT catalogado como fácil por tener que analizar los movimientos de una wallet Ethereum.

#### Nos vemos en un próximo. ¡Feliz hacking! ☠