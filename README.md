# Projet 1 — Analyse des journaux d'un pare-feu

**Nom / Prénom :** Abdou DIOP

## Lancer le projet
```bash
pip install -r requirements.txt
python analyse.py
```
Le script nettoie `data/logs_reseau.csv`, écrit `resultats.json` et enregistre les figures dans `figures/`.
Le compte rendu est dans [`rapport.md`](rapport.md).
## Résultats

| Clé | Valeur |
| :--- | :--- |
| nb_lignes_apres_nettoyage | 5440 |
| top_port | 443 |
| taux_deny_pct | 13.57 |
| ip_scanner | 192.168.1.99 |
| ip_exfiltration | 192.168.1.11 |
