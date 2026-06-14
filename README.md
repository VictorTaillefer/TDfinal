# ANSSI Cyber-Enricher & Analyzer

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Pandas](https://img.shields.io/badge/Library-Pandas-150458.svg)](https://pandas.pydata.org/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-F7931E.svg)](https://scikit-learn.org/)
[![Data-Source](https://img.shields.io/badge/Source-CERT--FR%20%2F%20ANSSI-red.svg)](https://www.cert.ssi.gouv.fr/)

Ce projet est une solution complète pour la **collecte, l'enrichissement et l'analyse de données de vulnérabilités** issues du CERT-FR (ANSSI). Il permet de croiser les alertes françaises avec les bases de données mondiales **MITRE (CVE)** et **FIRST (EPSS)** pour obtenir une vision 360° du risque cyber.

---

## Fonctionnalités Clés

-  **Extraction Dynamique & Automatisée** : 
  - Scan des bulletins locaux (JSON).
  - Récupération en temps réel via les **flux RSS** de l'ANSSI.
  - Identification précise des CVE par expressions régulières (Regex).
-  **Enrichissement Multi-Sources** : Corrélation via fichiers locaux ou **APIs (MITRE & FIRST)** pour récupérer :
  - Scores **CVSS v3.1** (Gravité technique).
  - Scores **EPSS** (Probabilité d'exploitation réelle).
  - Types de vulnérabilité (**CWE**).
  - Produits et versions affectés.
-  **Analyse de Données & Visualisation** : Notebook complet pour explorer les tendances, les éditeurs les plus touchés et la distribution de la sévérité.
-  **Intelligence Artificielle** :
  - **Clustering (K-Means)** : Regroupement automatique des vulnérabilités par profil de risque.
  - **Prédiction (Random Forest)** : Modèle capable de prédire la probabilité d'exploitation.
-  **Système d'Alerte** : Notification automatique par email pour les vulnérabilités jugées critiques (CVSS ≥ 9.0).

---

##  Structure du Projet

```text
 TDfinal
├──  main.py                # Script principal d'enrichissement (JSON -> CSV)
├──  dataset_use.ipynb      # Analyse, Machine Learning et Système d'alerte
├──  scrapSample.ipynb       # Scraping initial des données
├──  donnees_anssi_enrichies.csv  # Base de données consolidée
├──  data/                  # Données brutes (non incluses ou échantillons)
│   ├──  alertes/           # Bulletins d'alertes ANSSI
│   ├──  Avis/              # Avis de sécurité ANSSI
│   ├──  mitre/             # Fichiers CVE du MITRE
│   └──  first/             # Données EPSS du FIRST
└──  README.md              # Vous êtes ici !
```

---

##  Installation & Utilisation

### 1. Prérequis
Assurez-vous d'avoir Python 3.8+ installé.
```bash
pip install pandas scikit-learn matplotlib seaborn
```

### 2. Enrichissement via fichiers locaux (Données massives)
>  **Important** : Pour générer le fichier principal `donnees_anssi_enrichies.csv` via `main.py`, vous devez impérativement ajouter le dossier `data/` à la racine du projet. Ce dossier doit contenir les sous-dossiers `alertes/`, `Avis/`, `mitre/` et `first/` peuplés de leurs fichiers JSON respectifs.

```bash
python main.py
```

### 3. Extraction dynamique (Scraping & APIs)
Si vous souhaitez générer un jeu de données à partir des dernières publications en ligne :
1. Ouvrez le notebook `scrapSample.ipynb`.
2. Exécutez les cellules pour scraper les flux RSS de l'ANSSI et interroger les APIs MITRE/FIRST.
3. Cela générera le fichier `sample_data_from_scrap.csv`.

### 4. Analyse, ML & Alerting
Ouvrez `dataset_use.ipynb` pour exploiter les données générées (soit le CSV massif, soit l'échantillon scrapé) :
- Visualiser les graphiques statistiques.
- Entraîner les modèles de Machine Learning.
- Configurer et tester les alertes emails.

---

##  Machine Learning

Le projet utilise deux approches complémentaires :

1.  **K-Means Clustering** : Permet de segmenter les vulnérabilités en 3 groupes (Risque Faible, Modéré, Élevé) en croisant la gravité (CVSS) et l'exploitabilité (EPSS).
2.  **Random Forest Regressor** : Entraîné pour estimer le score EPSS d'une nouvelle vulnérabilité en fonction de son type (CWE) et de sa gravité (CVSS).

---

##  Système d'Alerte

Le module d'alerte intégré permet de ne jamais rater une menace critique. 
- **Cible** : Vulnérabilités avec un score **CVSS ≥ 9.0**.
- **Contenu** : Description, produit affecté, versions concernées et lien direct vers le bulletin ANSSI.

---

##  Technologies Utilisées

- **Langage** : Python 
- **Data Science** : Pandas, Numpy
- **Machine Learning** : Scikit-Learn (K-Means, RandomForest)
- **Visualisation** : Matplotlib, Seaborn
- **Automation** : Smtplib (Email), Regex, OS

---

*Développé dans le cadre du Mastercamp (TD9).*
