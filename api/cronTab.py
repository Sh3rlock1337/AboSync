
import mysql.connector
import resend
from mysql.connector import Error
import time

#for email sending with resend
RESEND_API_KEY = ""

def connect_to_database():
    try:
        connection = mysql.connector.connect(
            host='localhost',  # z.B. 'localhost'
            database='abosub_db',
            user='root',
            password='')
        if connection.is_connected():
            return connection
    except Error as e:
        print("Fehler beim Verbinden zur MySQL DB", e)
        return None

def query_database(connection):
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM api_registrationmodeldata")  # z.B. 'SELECT * FROM table'
        records = cursor.fetchall()
        tupel = []
        for row in records:
       #     print("Reihe: " + str(row))
            # Zugriff auf die einzelnen Werte
            zweiter_wert = row[1]
            dritter_wert = row[2]
            vierter_wert = row[3]
            if vierter_wert == 2 or dritter_wert==1:
                if dritter_wert == 1:
                    tupel.append(zweiter_wert)


        try:
            cursor.execute("SELECT * FROM api_billingintervalls")  # z.B. 'SELECT * FROM table'
            interval_list = cursor.fetchall()

            create_datencompact(tupel, interval_list, connection)
        except Error as e:
            print(e)

    except Error as e:
        print("Fehler bei der MySQL-Abfrage", e)

from datetime import datetime, timedelta  # Korrekter Import

def check_for_billing(user_id, connection, first_name, last_name, interval_list):
    print(user_id)
    try:
        neuercursor = connection.cursor()
        neuercursor.execute("SELECT * FROM auth_user")  # z.B. 'SELECT * FROM table'
        authUser_record = neuercursor.fetchall()



        cursor = connection.cursor()
        cursor.execute("SELECT * FROM api_abo WHERE besitzer = %s", (user_id,))  # Nutze parameterisierte Abfragen
        abo_liste = cursor.fetchall()
        current_date = datetime.now()

        for eintrag in abo_liste:
            datum = eintrag[5]  # Angenommen, dies ist ein datetime.date Objekt
            abo_name = eintrag[1]

            abo_interval = eintrag[7]
            abo_preis = eintrag[3]
            # Einen Tag subtrahieren
            datum_minus_ein_tag = datum - timedelta(days=1)

            # Berechne das Intervall
            interval = interval_list[abo_interval-1][1]
          #  print("----")
          #  print(interval)
          #  print(abo_name)
          #  print(datum_minus_ein_tag.strftime("%m-%d"), current_date.strftime("%m-%d"))
          #  print("----")

            # Prüfe, ob eine Übereinstimmung besteht

            if ist_abrechnungsdatum(interval, datum_minus_ein_tag.strftime("%Y-%m-%d"), current_date.strftime("%Y-%m-%d")):

                print("sendmail")
                print(abo_name)
                for authUser in authUser_record:
                    print("eintrag")
                    if authUser[0] == user_id:
                        print("user gefunden")
                        print(authUser[7])
                        send_email(
                            "AboSync Payment reminder",
                            (f'<!DOCTYPE html>'
                             f' <html> '
                             f' <head> </head>'
                             f'<body style="background-color: white; padding: 20%">'
                             f'<div style="background-color: #F5F5F5; padding: 30px; height: 400px; align-items: center;">'
                             f'<img src="/api/Logo-Voll.svg">'
                             f'<h1 style="display: flex; justify-content: center; margin-bottom: 30px;">Abrechnung zu Ihrem Vertrag {abo_name}</h1>'
                             f'<p style="display: flex; justify-content: center;">'
                             f'Guten Tag {first_name} {last_name},'
                             f'<br>'
                             f'<br>'
                             f'wir möchten Sie daran erinnern, dass die Abrechnung in Höhe von {abo_preis}€ zu Ihrem Vertrag {abo_name} am {datum.strftime("%d") }.{current_date.strftime("%m")} ansteht.'
                             f'<br>'
                             f'<br>'
                             f'Bitte prüfen Sie, ob Ihr Konto ausreichend gedeckt ist.'
                             f'<br>'
                             f'<br>'
                             f'Vielen Dank für Ihr Vertrauen.'
                             f'<br>'
                             f'<br>'
                             f'Mit freundlichen Grüßen'
                             f'<br>'
                             f'<br>'
                             f'Ihr AboSync-Team'
                             f'</p>'
                             f'</div>'
                             f'</body>'
                             f'<html>'),
                            f"{authUser[7]}"
                        )


    except Exception as e:
        print("Fehler: ", e)


def ist_abrechnungsdatum(interval, abrechnungsdatum_str, heute_str):
    # Konvertiere die Datumsstrings in datetime Objekte
    abrechnungsdatum = datetime.strptime(abrechnungsdatum_str, "%Y-%m-%d")
    heute = datetime.strptime(heute_str, "%Y-%m-%d")

    # Berechne die Differenz in Monaten und Jahren
    monate_diff = (heute.year - abrechnungsdatum.year) * 12 + heute.month - abrechnungsdatum.month
    tage_diff = heute.day - abrechnungsdatum.day

    # Überprüfe, ob die Differenz in Monaten ein Vielfaches des Intervalls ist und ob die Tage übereinstimmen
    return monate_diff % interval == 0 and tage_diff == 0


def create_datencompact(tupel, interval_liste, connection):
    # Beginn der Funktion
    gespeicherte_erste_werte = []
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT * FROM api_companydata")  # z.B. 'SELECT * FROM table'
        records = cursor.fetchall()
        for record in records:
            for userid in tupel:
                if record[0] == (userid):
                    if record[8]:
                        print(f"NOFITIFCATION AKTIV: {record[8]} bei Nutzer {userid} ")
                        first_name = record[2]
                        last_name = record[4]
                        check_for_billing(userid, connection, first_name, last_name, interval_liste)

            # Prüfe, ob der dritte Wert 1 oder 2 ist
    except Error as e:
        print("Fehler bei der Datenabfrage", str(e))

resend.api_key = RESEND_API_KEY

def send_email(subject, html_body, recipient_email):
    params: resend.Emails.SendParams = {
        "from_": "No-reply <noreply@abosync.com>",
        "to": [recipient_email],
        "subject": subject,
        "html": html_body,
    }

    try:
        resend.Emails.send(params)
        print("E-Mail wurde erfolgreich gesendet an ", recipient_email)
    except Exception as e:
        print("Fehler beim Senden der E-Mail: ", e)





def main():
    connection = connect_to_database()
    if connection is not None:
        query_database(connection)
        time.sleep(20)  # Wartezeit in Sekunden zwischen den Abfragen


if __name__ == "__main__":
    main()
