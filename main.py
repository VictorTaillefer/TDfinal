import os
import json
import pandas as pd
import re


DIR_ALERTES = "./data/alertes"
DIR_AVIS = "./data/Avis"
DIR_MITRE = "./data/mitre"
DIR_FIRST = "./data/first"

donnees_enrichies = []
cve_pattern = r"CVE-\d{4}-\d{4,7}"

def lire_json_local(chemin_fichier):
    try:
        with open(chemin_fichier, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None

def get_severity(score):
    try:
        score = float(score)
        if score == 0.0: return "None"
        elif score < 4.0: return "Low"
        elif score < 7.0: return "Medium"
        elif score < 9.0: return "High"
        else: return "Critical"
    except:
        return "Non disponible"

def extraire_et_enrichir(dossier_source, type_bulletin):
    """Parcourt les bulletins, extrait les CVE et les enrichit avec MITRE et FIRST."""
    if not os.path.exists(dossier_source):
        print(f"Dossier introuvable : {dossier_source}")
        return

    fichiers_bulletins = os.listdir(dossier_source)
    print(f"Traitement de {len(fichiers_bulletins)} {type_bulletin}s depuis {dossier_source}...")

    for nom_fichier in fichiers_bulletins:
        chemin_bulletin = os.path.join(dossier_source, nom_fichier)
        data_bulletin = lire_json_local(chemin_bulletin)
        
        if not data_bulletin:
            continue
            
        # Extraction des CVE
        cve_list = list(set(re.findall(cve_pattern, str(data_bulletin))))
        
        # Données de base du bulletin
        id_anssi = nom_fichier.replace('.json', '') 
        titre = data_bulletin.get("title", "Titre non disponible")
        date_pub = data_bulletin.get("published", "Date non disponible")
        
        # Reconstruction du lien (si type_bulletin est 'Alerte' on met 'alerte', etc.)
        lien_type = "alerte" if "ALE" in id_anssi else "avis"
        lien = f"https://www.cert.ssi.gouv.fr/{lien_type}/{id_anssi}/"
        
        for cve_id in cve_list:
            
            chemin_mitre = os.path.join(DIR_MITRE, f"{cve_id}.json")
            if not os.path.exists(chemin_mitre):
                 chemin_mitre = os.path.join(DIR_MITRE, cve_id) 

            data_mitre = lire_json_local(chemin_mitre)
            
            cvss_score = "Non disponible"
            cwe = "Non disponible"
            description = "Non disponible"
            editeur = "Non disponible"
            produit = "Non disponible"
            versions = "Non disponible"
            
            if data_mitre:
                cna = data_mitre.get("containers", {}).get("cna", {})
                
                # Score CVSS
                try:
                    metrics = cna.get("metrics", [])
                    for m in metrics:
                        if "cvssV3_1" in m:
                            cvss_score = m["cvssV3_1"].get("baseScore", "Non disponible")
                            break
                        elif "cvssV3_0" in m:
                            cvss_score = m["cvssV3_0"].get("baseScore", "Non disponible")
                            break
                except: pass
                
                # CWE
                try:
                    problem_types = cna.get("problemTypes", [])
                    if problem_types:
                        cwe = problem_types[0].get("descriptions", [{}])[0].get("cweId", "Non disponible")
                except: pass

                # Description
                try:
                    description = cna.get("descriptions", [{}])[0].get("value", "Non disponible")
                except: pass

                # Produits affectés (Editeur, Produit, Versions)
                try:
                    affected = cna.get("affected", [])
                    if affected:
                        editeur = affected[0].get("vendor", "n/a")
                        produit = affected[0].get("product", "n/a")
                        
                        versions_affectees = []
                        for v in affected[0].get("versions", []):
                            if v.get("status") == "affected":
                                versions_affectees.append(v.get("version", ""))
                        if versions_affectees:
                            versions = ", ".join(versions_affectees)
                except: pass

            base_severity = get_severity(cvss_score)

            # enrichissement
            chemin_first = os.path.join(DIR_FIRST, f"{cve_id}.json")
            if not os.path.exists(chemin_first):
                 chemin_first = os.path.join(DIR_FIRST, cve_id)

            data_first = lire_json_local(chemin_first)
            epss_score = "Non disponible"
            
            if data_first:
                epss_data = data_first.get("data", [])
                if epss_data:
                    epss_score = epss_data[0].get("epss", "Non disponible")

           
            ligne = {
                "ID ANSSI": id_anssi,
                "Titre ANSSI": titre,
                "Type": type_bulletin,
                "Date": date_pub,
                "CVE": cve_id,
                "CVSS": cvss_score,
                "Base Severity": base_severity,
                "CWE": cwe,
                "EPSS": epss_score,
                "Lien": lien,
                "Description": description,
                "Éditeur": editeur,
                "Produit": produit,
                "Versions affectées": versions
            }
            donnees_enrichies.append(ligne)


extraire_et_enrichir(DIR_ALERTES, "Alertes")
extraire_et_enrichir(DIR_AVIS, "Avis")


# DataFrame

df_final = pd.DataFrame(donnees_enrichies)

# Nettoyage des colonnes numériques
df_final['CVSS'] = pd.to_numeric(df_final['CVSS'], errors='coerce')
df_final['EPSS'] = pd.to_numeric(df_final['EPSS'], errors='coerce')
df_final['Date'] = pd.to_datetime(df_final['Date'], format='mixed', errors='coerce')

print("\n--- Aperçu du DataFrame Consolidé ---")
print(df_final.head())

# Sauvegarde
df_final.to_csv("donnees_anssi_enrichies.csv", index=False)
print("\nDonnées sauvegardées avec succès dans 'donnees_anssi_enrichies.csv' ! ")