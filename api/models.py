from django.db import models

# Create your models here.
# api/models.py
from django.db import models
from django.utils import timezone

class User(models.Model):
   username = models.CharField(max_length=100)
   password = models.CharField(max_length=100)

   class Meta:
       app_label = 'api'

class UserProfile(models.Model):

    username = models.CharField(max_length=255, unique=True)

    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=255)
    firmenname = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    postleitzahl = models.CharField(max_length=10)
    street = models.CharField(max_length=255, default="")

    ort = models.CharField(max_length=255)
    land = models.CharField(max_length=255)
    password = models.CharField(max_length=255)

class companyData(models.Model):
    userid = models.IntegerField(User, unique=True, default=0)  # Verknüpfung mit der Benutzer-ID
    first_name = models.CharField(max_length=255)
    firmenname = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    street = models.CharField(max_length=255, default="")
    postleitzahl = models.CharField(max_length=10)
    ort = models.CharField(max_length=255)
    land = models.CharField(max_length=255)
    mailnotification = models.BooleanField(default=True)

class EmailCode(models.Model):
    emailcode = models.IntegerField()
    userid = models.IntegerField(User)
class registrationModelData(models.Model):
    userid = models.PositiveIntegerField()
    emailverification = models.PositiveIntegerField(default=0)
    subvalue = models.PositiveIntegerField(default=0)
    stripe_subscription_id = models.CharField(max_length=255, default="")
    stripe_customer_id = models.CharField(max_length=255, default="")


    def __str__(self):
        return f'User ID: {self.userid}'

class Kategorie(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    def __str__(self):
        return self.name


class BillingIntervalls(models.Model):
    id = models.AutoField(primary_key=True)
    interval = models.IntegerField()



    def __str__(self):
        return self.name

class ExampleContract(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255)
    kategories = models.ForeignKey(Kategorie, on_delete=models.CASCADE)
    def __str__(self):
        return self.name




class Abo(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, default="")
    besitzer = models.IntegerField()
    preis = models.CharField(max_length=255, default="0")
    kategorie = models.ForeignKey(Kategorie, on_delete=models.CASCADE)
    rechnungsintervall = models.ForeignKey(BillingIntervalls, on_delete=models.CASCADE)
    status = models.BooleanField(default=True)
    abrechnungsdatum = models.DateField(default=timezone.now)
    imageid = models.IntegerField(default=0)


class ImageModel(models.Model):
    name = models.CharField(max_length=100)
    image_blob = models.BinaryField()
    owner = models.IntegerField(default=0)
    aboid = models.IntegerField(default=0)


