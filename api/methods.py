import random
import re
from django.core.mail import send_mail

from api.models import User

from datetime import datetime

def send_mail_method(subject, text_part, html_part, to):
    send_mail(subject, text_part, "abosync@abosync.com", [to], fail_silently=False, html_message=html_part)

def generate_email_content(user, mailcode):
    return f"""
    <!DOCTYPE html>
    <html>
    <head></head>
    <body style="background-color: white; padding: 20%">
        <div style="background-color: #F5F5F5; padding: 30px; height: 400px; align-items: center;">
            <img src="/api/Logo-Voll.svg">
            <h1 style="display: flex; justify-content: center; margin-bottom: 30px;">AboSync</h1>
            <p style="display: flex; justify-content: center;">
                Guten Tag {user.first_name} {user.last_name},<br><br>
                Ihr AboSync Verifizierungscode lautet: <strong>{mailcode}</strong>.<br>
                Ihr AboSync Benutzername ist: {user.username}<br><br>
                Vielen Dank für Ihr Vertrauen.<br><br>
                Mit freundlichen Grüßen<br><br>
                Ihr AboSync-Team
            </p>
        </div>
    </body>
    </html>
    """


def is_valid_email(email):
    # Überprüfen, ob die E-Mail-Adresse gültig ist
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None


def check_email_exists(email):
    # Überprüfen, ob die E-Mail-Adresse in der Datenbank existiert
    user_exists = User.objects.filter(email=email).exists()
    return user_exists

def generate_six_random_numbers_as_string():
    return ''.join(random.choices("123456789", k=6))


def is_billing_month(subscription, current_date):
    billing_date = datetime.strptime(str(subscription.abrechnungsdatum), "%Y-%m-%d")
    interval = int(subscription.rechnungsintervall.interval)

    # Calculate the difference in months and adjust the year and month of the billing date
    month_diff = (current_date.year - billing_date.year) * 12 + (current_date.month - billing_date.month)
    billing_date = billing_date.replace(year=current_date.year, month=((billing_date.month - 1 + month_diff) % 12) + 1)

    if interval == 1:
        # Monthly interval logic

        if current_date.day == billing_date.day or billing_date.day - 1 == current_date.day:

            return 'red'

        elif current_date.day < billing_date.day:
            return 'yellow'
        elif current_date.day > billing_date.day:
            return 'green'
    else:
        # Other intervals logic
        if month_diff % interval == 0:
            # Check if current date is within the correct interval month
            if billing_date.day == current_date.day or billing_date.day - 1 == current_date.day:
                return 'red'
            elif current_date.day < billing_date.day:
                return 'yellow'
            elif current_date.day > billing_date.day:
                return 'green'

    return None

