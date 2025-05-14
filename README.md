# Smol - HackMyVM (Medium)
 
![Smol.png](Smol.png)

## Übersicht

*   **VM:** Smol
*   **Plattform:** [https://hackmyvm.eu/machines/machine.php?vm=Smol] 
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 10. Februar 2025
*   **Original-Writeup:** https://alientec1908.github.io/Smol_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der Challenge "Smol" war es, User- und Root-Rechte auf der Maschine zu erlangen. Der Lösungsweg begann mit der Enumeration eines WordPress-Systems, das eine Schwachstelle (LFI/SSRF, CVE-2018-20463) im Plugin `jsmol2wp` aufwies. Diese LFI wurde genutzt, um die `wp-config.php` auszulesen und Datenbank-Zugangsdaten zu erhalten. Eine weitere LFI-Nutzung deckte eine modifizierte `hello.php`-Datei auf, die eine PHP-Backdoor enthielt. Über diese Backdoor wurde Remote Code Execution (RCE) erreicht, was zu einer Reverse Shell als Benutzer `www-data` führte. Anschließend wurden die Datenbank-Credentials verwendet, um auf MySQL zuzugreifen und Passwort-Hashes von WordPress-Benutzern zu extrahieren, von denen einige geknackt werden konnten. Der finale Schritt zur Root-Eskalation ist im Original-Writeup nicht detailliert beschrieben, führte aber zur Erlangung der Root-Flag.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `nikto`
*   `gobuster`
*   `wpscan`
*   `hydra`
*   `ffuf`
*   `john` (John the Ripper)
*   `hashcat`
*   `nc` (netcat)
*   `base64`
*   `mysql`
*   `stty`
*   `awk`
*   `grep`
*   `jq`
*   `find`
*   `ss`
*   Standard Linux-Befehle (`ls`, `cat`, `echo`, `printf`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Smol" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung im lokalen Netzwerk mit `arp-scan` (`192.168.2.164`).
    *   Umfassende Portscans mit `nmap` (TCP, UDP, SCTP, IPv6) identifizierten offene Ports 22 (SSH - OpenSSH 8.2p1) und 80 (HTTP - Apache 2.4.41).
    *   Identifizierung eines 302-Redirects auf Port 80 von der IP zu `www.smol.hmv`, was einen Eintrag in `/etc/hosts` erforderte.

2.  **Web Enumeration & Schwachstellensuche:**
    *   `nikto` und manuelle Inspektion bestätigten eine WordPress-Installation.
    *   `curl` zur Enumeration von WordPress-Benutzern über die REST API (`/index.php/wp-json/WP/V2/users/`). Gefundene User: `admin`, `wp`, `think`.
    *   `wpscan` lieferte detaillierte Informationen: WordPress 6.7.1, Theme `popularfx` 1.2.5 (veraltet), Plugin `akismet` 5.2 (veraltet).
    *   **Kritischer Fund durch `wpscan`:** Plugin `jsmol2wp` Version 1.07 mit bekannten Schwachstellen: Unauthenticated XSS (CVE-2018-20462) und Unauthenticated SSRF/LFI (CVE-2018-20463).
    *   Weitere User durch `wpscan` enumeriert: `gege`, `diego`, `xavi`.

3.  **Initial Access (LFI zu RCE):**
    *   Ausnutzung der LFI-Schwachstelle (CVE-2018-20463) im `jsmol2wp`-Plugin mittels `curl` und `php://filter` Payload (`http://www.smol.hmv/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=../../../../wp-config.php`) zum Auslesen der `wp-config.php`.
    *   Erlangung von Datenbank-Zugangsdaten: `wpuser`:`kbLSF2Vop#lw3rjDZ629*Z%G`.
    *   Verwendung von `ffuf` mit der LFI-Schwachstelle zum Fuzzen nach Dateien; Fund der Datei `wp-content/plugins/hello.php`.
    *   Auslesen der `hello.php` via LFI: Entdeckung einer modifizierten Version des "Hello Dolly"-Plugins, die eine PHP-Backdoor enthielt (`eval(base64_decode('...'))`), welche `system($_GET['cmd'])` ausführte.
    *   Ausnutzung der RCE über die Backdoor durch Aufruf von `http://www.smol.hmv/wp-admin/?cmd=[BEFEHL]`.
    *   Hochladen eines Reverse-Shell-Skripts (`rever.sh`) vom Angreifer-Server auf das Ziel nach `/tmp/rev.sh` mittels `curl` (via RCE).
    *   Ausführen des Skripts `bash /tmp/rev.sh` (via RCE), um eine Reverse Shell als Benutzer `www-data` zu erhalten.

4.  **Post-Exploitation / Privilege Escalation (von `www-data` zu User-Context/weiterer Enumeration):**
    *   Login in die MySQL-Datenbank mit den zuvor erlangten Credentials (`wpuser`).
    *   Auslesen der `wp_users`-Tabelle, um WordPress-Benutzer-Passwort-Hashes (phpass-Format) zu erhalten.
    *   Offline-Cracking der Hashes mit `john` und `hashcat` unter Verwendung der `rockyou.txt`-Wortliste. Geknackte Passwörter: `diego`:`sandiegocalifornia`, `gege`:`hero_gege@hotmail.com`.
    *   Überprüfung von `sudo -l` für `www-data` ergab keine direkten `sudo`-Rechte.
    *   Suche nach SUID-Binaries (`find / -type f -perm -4000`) zeigte Standard-Binaries; `pkexec` erforderte Authentifizierung.

5.  **Privilege Escalation (von `www-data` zu root):**
    *   Der detaillierte Weg zur Eskalation auf Root-Rechte ist im ursprünglichen Writeup nicht dokumentiert. Die Root-Flag wurde jedoch erlangt, was auf weitere nicht beschriebene Eskalationsschritte hindeutet.

## Wichtige Schwachstellen und Konzepte

*   **Veraltetes WordPress-Plugin (jsmol2wp CVE-2018-20463):** Ausnutzung einer Local File Inclusion (LFI) / Server Side Request Forgery (SSRF) Schwachstelle, um sensible Dateien (`wp-config.php`, `hello.php`) auszulesen.
*   **PHP-Backdoor in modifizierter Plugin-Datei (hello.php):** Eine versteckte `eval(base64_decode(...))` Funktion in einer Standard-WordPress-Datei ermöglichte Remote Code Execution (RCE).
*   **WordPress REST API User Enumeration:** Die offene REST API erlaubte das Auflisten von Benutzernamen und zugehörigen Details.
*   **Speicherung von Datenbank-Credentials in `wp-config.php`:** LFI auf diese Datei kompromittierte die Datenbankzugangsdaten.
*   **Schwache Passwörter in der Datenbank:** WordPress-Benutzer-Hashes konnten offline geknackt werden, was auf die Verwendung schwacher Passwörter hindeutet.
*   **Fehlende HTTP Security Header:** Allgemeine Web-Sicherheitslücken wie das Fehlen von `X-Frame-Options` und `X-Content-Type-Options`.
*   **Passwort Cracking (phpass):** Verwendung von Tools wie John the Ripper und Hashcat zum Knacken der portablen WordPress-Passwort-Hashes.

## Flags

*   **User Flag (`user.txt`):** `45edaec653ff9ee06236b7ce72b86963`
*   **Root Flag (`root.txt`):** `bf89ea3ea01992353aef1f576214d4e4`

## Tags

`HackMyVM`, `Smol`, `Medium`, `LFI`, `RCE`, `WordPress`, `PHP Backdoor`, `MySQL`, `Password Cracking`, `jsmol2wp`, `CVE-2018-20463`, `Linux`, `Web`, `Privilege Escalation`
