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
git clone https://github.com/dein-repository.git
cd dein-repository

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
```sh
cd frontend
npm install
ng serve --open
```

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


