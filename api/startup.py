from django.db import connection, OperationalError
from django.core.management import call_command

from api.models import BillingIntervalls, Kategorie


# Ersetze mit deinen Modellen

def check_database_and_entries():
    try:
        # Prüfen, ob die Datenbankverbindung besteht
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")

        # Prüfen, ob die Tabelle 'api_kategorie' existiert
        table_name_kategorie = Kategorie._meta.db_table
        table_name_billing = BillingIntervalls._meta.db_table

        for table_name in [table_name_kategorie, table_name_billing]:
            with connection.cursor() as cursor:
                cursor.execute(f"SHOW TABLES LIKE '{table_name}'")
                if not cursor.fetchone():
                    print(f"Tabelle {table_name} existiert nicht. Führe Migrationen aus...")
                    call_command("migrate")

        # Prüfen, ob 'api_kategorie' bereits Einträge hat
        if not Kategorie.objects.exists():
            print("Füge Standardkategorien hinzu...")
            Kategorie.objects.bulk_create([
                Kategorie(id=1, name="Unterhaltung"),
                Kategorie(id=2, name="Arbeiten"),
                Kategorie(id=3, name="Essen & Ausgehen"),
                Kategorie(id=4, name="Gaming"),
                Kategorie(id=5, name="Versicherungen"),
                Kategorie(id=6, name="Fitness"),
            ])

        # Prüfen, ob 'api_billingintervalls' bereits Einträge hat
        if not BillingIntervalls.objects.exists():
            print("Füge Standard-Billing-Intervalle hinzu...")
            BillingIntervalls.objects.bulk_create([
                BillingIntervalls(id=1, interval=1),
                BillingIntervalls(id=2, interval=3),
                BillingIntervalls(id=3, interval=6),
                BillingIntervalls(id=4, interval=12),
            ])

    except OperationalError:
        print("Datenbankverbindung fehlgeschlagen. Stelle sicher, dass die Datenbank existiert.")
