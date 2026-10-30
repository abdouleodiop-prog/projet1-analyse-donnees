# Rapport — Analyse des journaux du pare-feu

## Résumé
Le journal contient 5 500 lignes, soit 5 440 après suppression de 60 doublons exacts. Le trafic est surtout du web (443 : 1 874 connexions, 80, 53), avec 13,57 % de connexions bloquées (DENY). Deux comportements sortent nettement du lot : un scan de ports massif et un transfert de données énorme depuis une caméra IoT. Les autres hôtes se comportent de façon homogène, avec des volumes faibles (médiane de 1 693 octets par connexion).

## Comportement suspect 1 : scan de ports (192.168.1.99)
- Ce PC a contacté **328 ports distincts** (entre 9 et 1023) sur une seule cible, `10.0.0.5`. Aucun autre hôte n'en contacte plus de 8 (voir `figures/ports_distincts_par_ip.png`).
- Les **400 connexions** ont lieu en 15 minutes, le 8 octobre entre 00:00 et 00:15, avec une durée moyenne de 0,05 s.
- Le pare-feu en a bloqué 383 sur 400 (96 %), mais **17 ont été autorisées**, ce qui révèle des ports ouverts à l'attaquant.

## Comportement suspect 2 : exfiltration de données (192.168.1.11)
- Cette caméra IoT a envoyé **259,9 Mo** au total, soit 94,8 % de tous les octets du journal (voir `figures/octets_par_appareil.png`).
- 38 transferts de plus de 1 Mo, **tous vers 8.8.8.8 sur le port 8080**, le 10 octobre. Ils représentent 259,5 Mo. Une caméra n'a aucune raison d'envoyer autant de données vers l'extérieur, et le port 8080 n'est pas son usage normal.
- Son trafic habituel est faible (médiane de 2 287 octets), donc le 10 octobre est une rupture nette.

## Autres points à surveiller
- **Telnet (port 23)** : 100 tentatives venant de 29 sources, dont 26 autorisées.
- **RDP (port 3389)** : 111 connexions, dont 30 autorisées.

## Recommandations
1. **Isoler l'IP 192.168.1.99** et enquêter sur le PC (malware ou poste détourné). Mettre en place une règle de détection de scan (par exemple plus de 50 ports distincts en une minute, puis blocage temporaire).
2. **Vérifier les 17 connexions autorisées** vers 10.0.0.5 et fermer les ports qui n'ont pas lieu d'être ouverts.
3. **Segmenter le réseau IoT** (VLAN dédié) et n'autoriser pour les caméras que les flux nécessaires, par exemple vers le serveur d'enregistrement. Bloquer tout le reste en sortie, et notamment les caméras vers Internet sur le port 8080.
4. **Surveiller le volume sortant** par appareil avec une alerte au-delà d'un seuil, et auditer le firmware et les mots de passe de la caméra 192.168.1.11.
5. **Fermer Telnet** (remplacer par SSH) et **restreindre RDP** (VPN ou liste d'IP autorisées).
