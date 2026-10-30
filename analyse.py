"""Projet 1 : analyse des journaux d'un pare-feu.

Usage : python analyse.py
Produit : resultats.json et figures/*.png
"""
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # pas d'affichage : on enregistre seulement les figures
import matplotlib.pyplot as plt
import pandas as pd

RACINE = Path(__file__).resolve().parent
CSV = RACINE / "data" / "logs_reseau.csv"
FIGURES = RACINE / "figures"


def nettoyer(df: pd.DataFrame) -> pd.DataFrame:
    """Doublons exacts, protocole en majuscules, bytes_sent manquants -> médiane."""
    df = df.drop_duplicates().copy()
    df["protocol"] = df["protocol"].str.upper()
    mediane = df["bytes_sent"].median()  # calculée après suppression des doublons
    df["bytes_sent"] = df["bytes_sent"].fillna(mediane)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def calculer_resultats(df: pd.DataFrame) -> dict:
    return {
        "nb_lignes_apres_nettoyage": int(len(df)),
        "top_port": int(df["dst_port"].value_counts().idxmax()),
        "taux_deny_pct": round(float((df["action"] == "DENY").mean() * 100), 2),
        "ip_scanner": str(df.groupby("src_ip")["dst_port"].nunique().idxmax()),
        "ip_exfiltration": str(df.groupby("src_ip")["bytes_sent"].sum().idxmax()),
    }


def figures(df: pd.DataFrame) -> None:
    FIGURES.mkdir(exist_ok=True)

    # 1. Top 10 des ports de destination
    ax = df["dst_port"].value_counts().head(10).plot(kind="bar", color="#3b6ea5")
    ax.set_title("Top 10 des ports de destination")
    ax.set_xlabel("Port de destination")
    ax.set_ylabel("Nombre de connexions")
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(FIGURES / "top_ports.png", dpi=120)
    plt.close()

    # 2. Connexions par heure de la journée
    ax = df.groupby(df["timestamp"].dt.hour).size().plot(kind="bar", color="#4c9f70")
    ax.set_title("Connexions par heure de la journée")
    ax.set_xlabel("Heure")
    ax.set_ylabel("Nombre de connexions")
    plt.tight_layout()
    plt.savefig(FIGURES / "connexions_par_heure.png", dpi=120)
    plt.close()

    # 3. Volume d'octets par type d'appareil (échelle log : l'exfiltration écrase le reste)
    ax = df.groupby("device_type")["bytes_sent"].sum().sort_values().plot(
        kind="barh", color="#c8553d"
    )
    ax.set_title("Octets envoyés par type d'appareil")
    ax.set_xlabel("Octets envoyés (échelle logarithmique)")
    ax.set_ylabel("Type d'appareil")
    ax.set_xscale("log")
    plt.tight_layout()
    plt.savefig(FIGURES / "octets_par_appareil.png", dpi=120)
    plt.close()

    # 4. Répartition ALLOW / DENY
    ax = df["action"].value_counts().plot(
        kind="pie", autopct="%1.1f%%", colors=["#4c9f70", "#c8553d"], ylabel=""
    )
    ax.set_title("Répartition ALLOW / DENY")
    plt.tight_layout()
    plt.savefig(FIGURES / "allow_deny.png", dpi=120)
    plt.close()

    # 5. Ports distincts contactés par IP source (top 10) : met en évidence le scanner
    ax = df.groupby("src_ip")["dst_port"].nunique().sort_values().tail(10).plot(
        kind="barh", color="#8e5ea2"
    )
    ax.set_title("Ports distincts contactés par IP source (top 10)")
    ax.set_xlabel("Nombre de ports distincts")
    ax.set_ylabel("IP source")
    plt.tight_layout()
    plt.savefig(FIGURES / "ports_distincts_par_ip.png", dpi=120)
    plt.close()


def main() -> None:
    brut = pd.read_csv(CSV)
    df = nettoyer(brut)
    resultats = calculer_resultats(df)
    figures(df)
    (RACINE / "resultats.json").write_text(
        json.dumps(resultats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(resultats, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
