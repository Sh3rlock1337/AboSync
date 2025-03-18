# AboSync - SaaS Subscription Manager

AboSync ist eine SaaS-Anwendung, die Benutzern hilft, ihre Abonnements zu verwalten und Benachrichtigungen über anstehende Zahlungen zu erhalten. Die Anwendung wurde mit Django (Backend) und Angular (Frontend) entwickelt und nutzt Stripe zur Abwicklung von Abonnements.

## Funktionen
- Benutzerregistrierung und Authentifizierung mit JWT (Django REST Framework Simple JWT)
- Verwaltung von Abonnements mit Kategorisierung und Rechnungsintervallen
- Integration von Stripe zur Zahlungsabwicklung
- Automatische Erinnerungs-E-Mails mit Resend
- API-Schnittstellen für das Frontend

## Installation

### Voraussetzungen
- Python 3.x
- Django
- Django REST Framework
- MySQL
- Node.js (für Angular Frontend)
- Resend API Key
- Stripe API Key

### Backend einrichten
```sh
# Repository klonen
git clone https://github.com/Sh3rlock1337/AboSync.git
cd backend

# Virtuelle Umgebung erstellen
python -m venv venv
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate  # Windows

# Abhängigkeiten installieren
pip install -r requirements.txt

# Datenbank migrieren
python manage.py migrate

# Superuser erstellen
python manage.py createsuperuser

# Server starten
python manage.py runserver
```

### Frontend einrichten
(https://github.com/Sh3rlock1337/AboSyncFrontend)

## Wichtige Dateien
- `models.py`: Enthält die Datenbankmodelle für Benutzer, Abonnements und Rechnungsintervalle
- `views.py`: Beinhaltet API-Endpunkte für die Benutzerverwaltung und Abonnementverwaltung
- `serializers.py`: Stellt die Serialisierungslogik für die API bereit
- `cronTab.py`: Script zur periodischen Überprüfung und Versendung von E-Mail-Benachrichtigungen
- `methods.py`: Utility-Methoden für E-Mail-Versand und Validierungen
- `urls.py`: Definiert die API-Endpunkte

## API-Endpunkte
- `POST /api/login/` - Benutzeranmeldung
- `POST /api/register/` - Benutzerregistrierung
- `GET /api/abolist/` - Liste aller Abonnements des Benutzers
- `POST /api/abopost/` - Neues Abonnement hinzufügen
- `GET /api/getallAbos/` - Übersicht über anstehende Zahlungen
- `POST /api/resetpassword/` - Passwort zurücksetzen
- `POST /api/stripecheckout/` - Stripe Checkout für Abonnements

## Automatische E-Mail-Benachrichtigungen
AboSync sendet Benachrichtigungen an Benutzer, wenn eine Abbuchung für ein Abonnement bevorsteht. Dies wird über das `cronTab.py`-Script gesteuert, das regelmäßig in der Datenbank prüft, ob Zahlungen anstehen.

## Lizenz
Dieses Projekt steht unter der MIT-Lizenz.
![Abosync Landing](https://github.com/user-attachments/assets/bb356dd0-027b-4a03-b130-92b96637a266)
![Abosync Landing2](https://github.com/user-attachments/assets/8ef3ea4a-c690-49e7-98b8-1cb56f249377)

![Abosync Login](https://github.com/user-attachments/assets/025dc5d6-791d-4232-9806-3db46429f0c3)

![Abosync Register](https://github.com/user-attachments/assets/62eb442b-7ba0-428c-b00e-6669782c8067)
![Abosync Abochoose](https://github.com/user-attachments/assets/bac35b91-2416-42fd-a0d4-85d7eec8d8d9)

![Abosync Dashboard](https://github.com/user-attachments/assets/9e54b4f2-99bf-4dca-a30f-a2baca85717c)
![Abosync Aboanlegen](https://github.com/user-attachments/assets/0298bd1b-e74c-44ca-aac6-a8d77a30bdd8)
![AboSync Detailview](https://github.com/user-attachments/assets/3c566dc1-c8e3-47b8-9260-a1d75a60fbca)
