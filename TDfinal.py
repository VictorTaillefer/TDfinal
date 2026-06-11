import pandas as pd
import feedparser


urls = {
    "Avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "Alertes": "https://www.cert.ssi.gouv.fr/alerte/feed/"
}

bulletins = []

for type_bulletin, url in urls.items():
    rss_feed = feedparser.parse(url)
    for entry in rss_feed.entries:
        bulletins.append({
            "id_bulletin": entry.link.split('/')[-2], # Extrait l'ID (ex: CERTFR-2024-ALE-001)
            "titre": entry.title,
            "type": type_bulletin,
            "date_publication": entry.published,
            "lien": entry.link
        })

print(f"{len(bulletins)} bulletins extraits avec succès.")