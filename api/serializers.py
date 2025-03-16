# api/serializers.py

from .models import User, companyData, registrationModelData, EmailCode, BillingIntervalls, Abo, ImageModel

from rest_framework import serializers
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    firmenname = serializers.CharField(max_length=255)
    first_name = serializers.CharField(max_length=255)
    last_name = serializers.CharField(max_length=255)
    postleitzahl = serializers.CharField(max_length=10)
    ort = serializers.CharField(max_length=255)
    land = serializers.CharField(max_length=255)
    street = serializers.CharField(max_length=255)
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password', 'street','firmenname', 'first_name', 'last_name', 'postleitzahl', 'ort', 'land', 'is_staff')

    extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        user.street = validated_data['street']
        user.firmenname = validated_data['firmenname']
        user.first_name = validated_data['first_name']
        user.last_name = validated_data['last_name']
        user.postleitzahl = validated_data['postleitzahl']
        user.ort = validated_data['ort']
        user.land = validated_data['land']
        user.save()
        return user
class CompanyDataSerializer(serializers.ModelSerializer):


    class Meta:
        model = companyData
        fields = '__all__'

class registrationModelDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = registrationModelData
        fields = '__all__'
class EmailCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailCode
        fields = '__all__'

from .models import Kategorie

class ItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = Kategorie
        fields = '__all__'
class BillingIntervalsSerializer(serializers.ModelSerializer):

    class Meta:
        model = BillingIntervalls
        fields = '__all__'

class AboSerializerGet(serializers.ModelSerializer):
    kategorie = ItemSerializer(read_only=True)
    rechnungsintervall = BillingIntervalsSerializer(read_only=True)
    class Meta:
        model = Abo
        fields = '__all__'
class AboSerializerPost(serializers.ModelSerializer):
  #  kategories = serializers.PrimaryKeyRelatedField(queryset=Kategorie.objects.all())
  #  rechnungsintervall = serializers.PrimaryKeyRelatedField(queryset=BillingIntervalls.objects.all())
    class Meta:
        model = Abo
        fields = '__all__'

class ImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ImageModel
        fields = ['id', 'name', 'image_blob', 'owner', 'aboid']

