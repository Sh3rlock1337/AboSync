import base64
import json

import threading
import time
from datetime import datetime, timedelta

from django.core.exceptions import ValidationError
from django.db import transaction, IntegrityError
from django.http import JsonResponse, HttpResponse, Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.views.decorators.csrf import csrf_exempt

from rest_framework import status, permissions, generics
from rest_framework.decorators import api_view, permission_classes
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser, MultiPartParser, FormParser
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

import stripe
from stripe import Subscription

from .methods import generate_six_random_numbers_as_string, send_mail_method, check_email_exists, is_valid_email, \
    generate_email_content
from .models import (
    User, companyData, EmailCode, Abo, ImageModel, UserProfile,
    BillingIntervalls, registrationModelData, Kategorie
)
from .serializers import (
    UserSerializer, CompanyDataSerializer, EmailCodeSerializer,
    BillingIntervalsSerializer, AboSerializerGet, AboSerializerPost,
    registrationModelDataSerializer, ItemSerializer
)

from backend import settings





def delete_stripe_account(request):
    stripe.api_key = settings.STRIPE_PRIVATE_KEY  # Verwenden Sie Ihren echten Stripe-Schlüssel
    try:
        # Retrieve the Stripe customer ID for the user
        customer = registrationModelData.objects.get(userid=request.user.id)
        stripe_customer_id = customer.stripe_customer_id

        # Check if the customer exists in Stripe
        if not stripe_customer_id:
            return Response({'error': 'Stripe customer not found'}, status=404)

        # Delete the customer in Stripe
        stripe.Customer.delete(stripe_customer_id)



        return Response({'message': 'Customer deleted successfully'}, status=204)

    except registrationModelData.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)
    except stripe.error.InvalidRequestError as e:
        return Response({'error': str(e)}, status=400)



class LoginView(APIView):
    parser_classes = [JSONParser]

    def post(self, request):
        if request.user.is_authenticated:
            return Response({'error': 'User already logged in'}, status=status.HTTP_400_BAD_REQUEST)

        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({'error': 'Username and password are required'}, status=400)

        user = authenticate(request, username=username, password=password)

        if user is None:
            return Response({'error': 'Invalid username or password'}, status=401)

        login(request, user)
        refresh = RefreshToken.for_user(user)

        return Response({'access_token': str(refresh.access_token)}, status=200)




@login_required
def get_logged_in_user(request):
    try:
        # Ensure that the user is authenticated before accessing attributes
        if request.user.is_authenticated:

            return JsonResponse({
                'username': request.user.username,
                'email': request.user.email,
                'id': request.user.id,
                'first_name': request.user.first_name,
                'last_name': request.user.last_name,

                # ... any other fields you need
            })
        else:
            # Handle the case where the user is not authenticated
            return JsonResponse({'error': 'User is not authenticated'}, status=401)
    except Exception as e:
        # Log any unexpected errors
        print(f"An error occurred: {str(e)}")
        return JsonResponse({'error': 'An error occurred'}, status=500)


# views.py

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return Response({'detail': 'Logout successful'}, status=status.HTTP_200_OK)


# accounts/views.py


class CompanyDataDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = companyData.objects.all()
    serializer_class = CompanyDataSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'userid'  # Setze das lookup_field auf 'userid'

    def get(self, request, *args, **kwargs):
        company = get_object_or_404(companyData, userid=request.user.id)
        if request.user.id == company.userid or request.user.is_staff:
            return super().retrieve(request, *args, **kwargs)
        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

    def delete(self, request, *args, **kwargs):
        if request.user.is_staff:
            return super().delete(request, *args, **kwargs)
        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)

    def put(self, request, *args, **kwargs):
        if request.user.is_staff:
            return super().update(request, *args, **kwargs)
        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)


class UserProfileCreateView(generics.CreateAPIView):
    queryset = UserProfile.objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        try:

            serializer.save()
            try:
                user = User.objects.get(username=serializer.validated_data['username'])

                registrationModelData.objects.create(userid=user.id, emailverification=0, subvalue=0)
                mailcode = generate_six_random_numbers_as_string()
                EmailCode.objects.create(emailcode=mailcode, userid=user.id)
                companyData.objects.create(userid=user.id,
                                           street=serializer.validated_data['street'],
                                           first_name=serializer.validated_data['first_name'],
                                           firmenname=serializer.validated_data['firmenname'],
                                           last_name=serializer.validated_data['last_name'],
                                           postleitzahl=serializer.validated_data['postleitzahl'],
                                           ort=serializer.validated_data['ort'],
                                           land=serializer.validated_data['land'])

                send_mail_method(
                    'Dein Bestätigungscode für AboSync',
                    f'Der Bestätigungscode lautet: {mailcode}',
                    generate_email_content(user, mailcode),
                    user.email
                )


            except User.DoesNotExist:
                print("Error user nicht gefunden")
        except IntegrityError as e:
            error_message = str(e)
            field_errors = {}
            if 'unique' in error_message.lower():
                if 'email' in error_message.lower():
                    field_errors['email'] = ['Diese Email ist bereits Registriert.']
                elif 'username' in error_message.lower():
                    field_errors['username'] = ['Der Nutzername ist bereits vergeben.']
            else:
                field_errors['non_field_errors'] = ['An unexpected error occurred.']

            if field_errors:
                raise ValidationError(field_errors)

    def post(self, request, *args, **kwargs):
        email_to_check = request.data.get('email')
        print("-----------request.data-------------")
        print(str(request.data))
        # Überprüfen, ob die E-Mail-Adresse gültig ist
        if not is_valid_email(email_to_check):
            return Response({'error': 'Ungültige Email.'}, status=status.HTTP_406_NOT_ACCEPTABLE)

        # Überprüfen, ob die E-Mail-Adresse in der Datenbank existiert
        if check_email_exists(email_to_check):
            return Response({'error': 'Diese Email ist bereits Registriert.'}, status=status.HTTP_406_NOT_ACCEPTABLE)

        try:
            response = super(UserProfileCreateView, self).post(request, *args, **kwargs)

            return Response({'detail': 'Successfully created'}, status=status.HTTP_201_CREATED)

        except ValidationError as e:
            error_details = e.detail
            email_error_messages = error_details.get('email', [])
            username_error_messages = error_details.get('username', [])

            if email_error_messages:

                return Response({'error': f'{email_error_messages[0]}'}, status=status.HTTP_406_NOT_ACCEPTABLE)
            elif username_error_messages:
                print(username_error_messages[0])
                return Response({'error': 'Der Benutzername existiert bereits!'}, status=status.HTTP_406_NOT_ACCEPTABLE)
            else:
                print("hier")
                return Response({'error': 'Eine E-Mail oder Nutzername kann nur einmal verwendet werden.'},
                                status=status.HTTP_406_NOT_ACCEPTABLE)





class RegistrationModelDataListCreateView(generics.ListCreateAPIView):
    queryset = registrationModelData.objects.all()
    serializer_class = registrationModelDataSerializer
    permission_classes = [IsAuthenticated]  # Fügen Sie die richtige Berechtigung hinzu


class IsOwnerOrAdminOrReadOnly(permissions.BasePermission):
    """
    Benutzerdefinierte Berechtigungsklasse, um sicherzustellen, dass der Benutzer nur seine eigenen Daten aktualisieren/löschen kann,
    es sei denn, der Benutzer ist ein Administrator.
    """

    def has_object_permission(self, request, view, obj):
        # Erlauben Sie Lesezugriff (GET) für alle Benutzer.
        if request.method in permissions.SAFE_METHODS:
            return True

        # Erlauben Sie Besitzern des Objekts oder Administratoren, es zu aktualisieren/löschen.
        return obj.id == request.user.id or request.user.is_staff


class RegistrationModelDataRetrieveUpdateDeleteView(generics.RetrieveUpdateDestroyAPIView):
    queryset = registrationModelData.objects.all()
    serializer_class = registrationModelDataSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdminOrReadOnly]

    def get_object(self):
        queryset = self.get_queryset()
        # Hier holen wir den Wert der UserID aus der URL
        userid = self.kwargs['userid']
        # Jetzt filtern wir die Datenbank nach dieser UserID
        obj = queryset.filter(userid=userid).first()
        return obj
#   api/registration-model/: Hier können Sie GET-Anfragen senden,
#   um alle Datensätze abzurufen, und POST-Anfragen, um neue Datensätze zu erstellen.
#   api/registration-model/<int:pk>/: Hier können Sie GET-Anfragen senden,
#   um einen bestimmten Datensatz abzurufen, PUT/PATCH-Anfragen,
#   um den Datensatz zu aktualisieren, und DELETE-Anfragen, um den Datensatz zu löschen.


@api_view(['GET', 'POST'])
@permission_classes([IsAdminUser])
def emailcode_list(request):
    if request.method == 'GET':
        emailcodes = EmailCode.objects.all()
        serializer = EmailCodeSerializer(emailcodes, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        serializer = EmailCodeSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()

            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def emailcode_detail(request, pk):
    try:
        emailcode = EmailCode.objects.get(userid=pk)
    except EmailCode.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)


    if request.method == 'POST':
        serializer = EmailCodeSerializer(emailcode)
        print("requested user " + str(request.user.id))
        dict_data = json.loads(request.body)
        print(dict_data)
        # user = User.objects.get(id=emailcode.id)
        try:
            if request.user.id == emailcode.userid or request.user.is_staff:

                if emailcode.emailcode == dict_data['input']:
                    print("success")
                    registrationModelDatas = registrationModelData.objects.get(userid=pk)
                    registrationModelDatas.emailverification = 1
                    registrationModelDatas.save()
                    return Response({"response": "successfull"}, status=status.HTTP_200_OK)
                else:
                    print(dict_data['input'])
                    print("not success")
                    return Response({"response": "wrongcode"}, status=status.HTTP_200_OK)

            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response(status=status.HTTP_406_NOT_ACCEPTABLE)






@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def kategories_list(request):
    if request.method == 'GET':
        kategorie = Kategorie.objects.all()
        serializer = ItemSerializer(kategorie, many=True)
        return Response(serializer.data)

    elif request.method == 'POST':
        if request.user.is_staff:
            serializer = ItemSerializer(data=request.data)
            if serializer.is_valid():
                name = request.data.get('name')
                existing_item = Kategorie.objects.filter(
                    name=name).first()  # Versuchen, ein Element mit dem gegebenen Namen zu finden

                if existing_item:
                    return Response({"message": "Das Element existiert bereits."}, status=400)

                serializer = ItemSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        else:
            return Response(status=404)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def kategorie_detail(request, pk):
    try:
        item = Kategorie.objects.get(pk=pk)
    except Kategorie.DoesNotExist:
        return Response(status=404)

    if request.method == 'GET':
        serializer = ItemSerializer(item)
        return Response(serializer.data)

    elif request.method == 'PUT':
        if request.user.is_staff:
            serializer = ItemSerializer(item, data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        return Response(status=404)

    elif request.method == 'DELETE':
        if request.user.is_staff:
            item.delete()
            return Response(status=204)
        return Response(status=404)


@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def billingintervals_list(request):
    if request.method == 'GET':
        billings = BillingIntervalls.objects.all()
        serializer = BillingIntervalsSerializer(billings, many=True)
        return Response(serializer.data)

    if request.method == 'POST':
        print("POST")
        if request.user.is_staff:
            serializer = BillingIntervalsSerializer(data=request.data)
            if serializer.is_valid():
                interval = request.data.get('interval')
                existing_item = BillingIntervalls.objects.filter(
                    interval=interval).first()  # Versuchen, ein Element mit dem gegebenen Namen zu finden

                if existing_item:
                    return Response({"message": "Das Element existiert bereits."}, status=400)

                serializer = BillingIntervalsSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        else:
            return Response(status=404)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def abolist(request):
    if request.method == 'GET':
        abo = Abo.objects.filter(besitzer=request.user.id)
        # HIER IST DER FEHLER
        serializer = AboSerializerGet(abo, many=True)
        getallImges = ImageModel.objects.filter(owner=request.user.id)
        for image in getallImges:
            print(image)  # or do something else with each image
            if image.aboid > 0:
                print("ABOID" + str(image.aboid))
                imageabochecker = Abo.objects.get(id=image.aboid)
                if (imageabochecker.besitzer == request.user.id):
                    print("JA BESITZER")
                    if (imageabochecker.imageid != image.id):
                        print("JA BESITZER UND NICHT GLEICH")
                        imageabochecker.imageid = image.id
                        imageabochecker.save()
                    else:
                        print("Abo bild schon vergeben")
        return Response(serializer.data)


@api_view(['GET', 'DELETE'])
@permission_classes([IsAuthenticated])
def aboget(request, pk):
    try:
        abo = Abo.objects.get(id=pk)
    except Abo.DoesNotExist:
        return Response(status=status.HTTP_404_NOT_FOUND)

    if request.method == 'GET':
        # Use the serializer to serialize the object, no need to call is_valid()
        serializer = AboSerializerGet(abo)
        if request.user.is_staff or request.user.id == abo.besitzer:

            try:
                image = ImageModel.objects.get(aboid=pk)
                print("Bild")
                abo.imageid = image.id
                abo.save()
            except ImageModel.DoesNotExist:
                print("Kein Bild")

            return Response(serializer.data)
        else:
            return Response(status=status.HTTP_403_FORBIDDEN)  # Use 403 for access denied
    if request.method == 'DELETE':
        if request.user.is_staff or request.user.id == abo.besitzer:
            ImageModel.objects.filter(aboid=pk).delete()

            abo.delete()

            return Response(status=204)
        return Response(status=404)
    return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)  # Method not allowed


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def abopost(request):
    if request.method == 'POST':
        data = request.data.copy()
        print("DATEN" + str(data))

        data.setdefault("abrechnungsdatum", timezone.now().date().isoformat())
        data['besitzer'] = request.user.id
        serializer = AboSerializerPost(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=201)
        else:
            #print("Validierungsfehler:", serializer.errors)
            return Response(serializer.errors, status=400)


def create_predefined_abo(id, preis):
    # Definieren der vordefinierten Abo-
    predefined_data = {
        'preis': preis,
        'rechnungsintervall': 1,
        'kategorie': 2,
        'abrechnungsdatum': timezone.now().date().isoformat(),  # Heutiges Datum im ISO-Format
        'name': 'AboSync',
        'besitzer': id  # ID des angemeldeten Benutzers als Besitzer
    }

    serializer = AboSerializerPost(data=predefined_data)
    print(":__------------------")
    print(serializer)
    if serializer.is_valid():
        serializer.save()
        return print(True)  # Erfolg: Rückgabe der Abo-Daten
    else:
        return print(False)


@api_view(['GET'])
def changeMailNotifier(request):
    try:
        # Logik zur Verarbeitung des Requests hier einfügen
        print("..........")

        print(request.user.id)
        company = companyData.objects.get(userid=request.user.id)
        print(company)
        print(company.mailnotification)
        # Hier sollte die Logik stehen, um den Status zu ändern
        # Angenommen, du erhältst den neuen Status aus dem Request
        status = company.mailnotification
        if status is not None:
            # Status aktualisieren
            if (status == True):
                company.mailnotification = False
            else:
                company.mailnotification = True
            company.save()
            return Response({'success': 'Mailnotification updated successfully'})
        else:
            # Kein Status bereitgestellt
            return Response({'error': 'No mailnotification status provided'}, status=status.HTTP_400_BAD_REQUEST)

    except companyData.DoesNotExist:
        # Kein entsprechendes Objekt gefunden
        return Response({'error': 'Company data not found'}, status=status.HTTP_404_NOT_FOUND)

    except Exception as e:
        # Ein anderer Fehler ist aufgetreten
        return Response({'error': f'An unexpected error occurred: {str(e)}'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def resetpassword(request):
    if request.user.is_authenticated:
        try:
            # Passwort aus der Anfrage holen
            password = request.data.get('password')

            # Überprüfen, ob ein Passwort bereitgestellt wurde
            if not password:
                return Response({'error': 'No password provided'}, status=400)

            # Optional: Validierung des Passworts (Mindestlänge, usw.)
            if len(password) < 6:
                return Response({'error': 'Password must be at least 6 characters long'}, status=400)

            # Passwort ändern
            user = request.user  # Nutze direkt request.user, da der Nutzer authentifiziert ist
            user.set_password(password)
            user.save()
            return Response({'success': 'Password updated successfully'})

        except User.DoesNotExist:
            # Dieser Block wird ausgeführt, wenn User.DoesNotExist Fehler auftritt
            return Response({'error': 'User does not exist'}, status=404)
        except Exception as e:
            # Dieser Block fängt alle anderen Fehler ab
            return Response({'error': f'An unexpected error occurred: {str(e)}'}, status=500)

    else:
        # Nutzer ist nicht authentifiziert
        return Response({'error': 'User is not authenticated'},
                        status=403)  # 403 Forbidden oder 401 Unauthorized kann hier verwendet werden


# IMAGES

class ImageUploadView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, format=None):
        image_file = request.FILES.get('image_blob')
        if not image_file:
            raise ValidationError("Kein Bild zum Hochladen gefunden")
        time.sleep(1)

        image_model = ImageModel()
        image_model.name = request.data.get('name', 'Unbenanntes Bild')
        image_model.image_blob = image_file.read()  # Lesen Sie die Binärdaten der Datei
        image_model.owner = request.data.get('owner', 0)
        try:
            latest_abo = Abo.objects.filter(besitzer=image_model.owner).latest('id')

            print("latest abo of user" + str(latest_abo.id))
        except Abo.DoesNotExist:
            raise Http404("Abo für den angegebenen Benutzer nicht gefunden")

        image_model.aboid = latest_abo.id
        image_model.save()

        return Response({"message": "Bild erfolgreich hochgeladen", "id": image_model.id},
                        status=status.HTTP_201_CREATED)


class ImageRetrieveView(APIView):
    def get(self, request, pk, format=None):
        try:
            image = ImageModel.objects.get(pk=pk)
        except ImageModel.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)

        return HttpResponse(image.image_blob, content_type='image/jpeg')



mailNotifier = False


@api_view(['GET'])
def setMailNotifier(request):
    global mailNotifier
    if request.user.is_staff:
        if mailNotifier == False:
            mailNotifier = True
            print("Starte MailNotifier")
            t = threading.Thread(target=mailNotifierThread, args=(request,))
            t.setName("MailNotifier")
            t.start()
            return Response({'success': f'{t.getName()} started successfully'})
        else:
            print("Aktive Threads:", threading.enumerate())
            print("Anzahl aktiver Threads:", threading.active_count())
            # Um einen bestimmten Thread zu finden und zu überprüfen, ob er lebt:
            for thread in threading.enumerate():
                if thread.getName() == "MailNotifier":
                    print("MailNotifier is alive:", thread.is_alive())
                    mailNotifier = False

                    return Response({'success': 'MailNotifier stopping successfully'})
            return Response({'error': 'MailNotifier already running'}, status=200)


    else:
        return Response(status=403)  # It's better to return a valid HTTP response



#######################################################################################################




@csrf_exempt
def stripe_webhook(request):
    # Sie müssen den tatsächlichen geheimen Schlüssel von Ihrem Stripe-Dashboard hier einfügen
    global customer_id_in_metadata
    webhook_secret = settings.WEBHOOK_KEY

    payload = request.body
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    print(sig_header)
    event = None

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError as e:
        print(e)
        # Ungültiger Payload
        return HttpResponse(status=401)
    except stripe.error.SignatureVerificationError as e:
        # Ungültige Signatur
        print(str(e))
        return HttpResponse(status=402)

    # Verarbeiten Sie das Webhook-Ereignis
    # print(event)

    if event['type'] == 'checkout.session.completed':
        payment_intent = event['data']['object']  # PaymentIntent-Objekt
        # Zugriff auf das 'customer'-Feld im 'metadata'
        customer_id_in_metadata = payment_intent['metadata']['customer']
        print('Kunden-ID aus metadata:', customer_id_in_metadata)
        try:
            Kunden = registrationModelData.objects.get(userid=customer_id_in_metadata)
            Kunden.stripe_subscription_id = payment_intent['subscription']
            Kunden.stripe_customer_id = payment_intent['customer']
            subscription_id = payment_intent['subscription']

            try:
                # Schritt 2: Rufen Sie die Subscription-Details ab
                subscription = stripe.Subscription.retrieve(subscription_id)

                # Schritt 3: Ermitteln Sie die Price ID
                for item in subscription['items']['data']:
                    price_id = item['price']['id']

                    # Schritt 4: Rufen Sie Produktinformationen ab
                    price = stripe.Price.retrieve(price_id)
                    product_id = price['product']
                    product = stripe.Product.retrieve(product_id)

                    print(f"Produkt gekauft: {product['name']} (ID: {product_id})")
                    if product['name'] == "AboSync Basic":
                        Kunden.subvalue = 1
                        create_predefined_abo(Kunden.userid, 4.99)

                    elif product['name'] == "AboSync Premium":
                        Kunden.subvalue = 2
                        create_predefined_abo(Kunden.userid, 7.99)
            except Exception as e:
                print(f"Fehler beim Abrufen der Produktinformationen: {e}")
            Kunden.save()
        except:
            print("Kunde nicht gefunden")
        print('PaymentIntent was successful!')
        print("Zahlung erfolgreich für:", payment_intent['amount_total'])
        print(payment_intent)

        print(payment_intent['customer'])
        print(payment_intent['subscription'])
    if event['type'] == 'customer.deleted':
        customer_id = event['data']['object']['id']
        # Fügen Sie hier Ihre Logik zum Löschen des Kunden aus Ihrer Datenbank ein
        print(f'Kunde mit ID {customer_id} wurde gelöscht.')
        Kunden = registrationModelData.objects.get(stripe_customer_id=customer_id)
        Kunden.stripe_customer_id = ""
        Kunden.save()

    if event['type'] == 'customer.subscription.deleted':
        subscription_event = event['data']['object']
        stripe_subscription_id = subscription_event['id']
        print(stripe_subscription_id)
        # Suchen Sie das Abonnement in Ihrer Datenbank und aktualisieren Sie es
        try:

            Kunden = registrationModelData.objects.get(stripe_subscription_id=stripe_subscription_id)
            Kunden.subvalue = 0
            Kunden.save()

            print(f"Abonnement {stripe_subscription_id} wurde als beendet markiert.")
        except Subscription.DoesNotExist:

            print(f"Abonnement {stripe_subscription_id} nicht in der Datenbank gefunden.")

    # Anderen Ereignistypen verarbeiten...

    return HttpResponse(status=200)








@api_view(['GET'])
def create_customer_portal_session(request):
    stripe.api_key = settings.STRIPE_PRIVATE_KEY  # Verwenden Sie Ihren echten Stripe-Schlüssel

    try:
        # Überprüfen, ob der Nutzer existiert
        Kunde = registrationModelData.objects.get(id=request.user.id)
    except registrationModelData.DoesNotExist:
        # Wenn der Nutzer nicht existiert, gebe eine Fehlermeldung zurück
        return Response({'error': 'Nutzer nicht gefunden'}, status=200)

    # Überprüfen, ob Kunde.stripe_customer_id vorhanden und nicht null ist
    if not Kunde.stripe_customer_id:
        # Wenn stripe_customer_id null oder nicht vorhanden ist, gebe eine Fehlermeldung zurück
        return Response({'error': 'Nutzer bei Stripe nicht gefunden'}, status=200)

    # Erstelle die Session für das Kundenportal
    session = stripe.billing_portal.Session.create(
        customer=Kunde.stripe_customer_id,
        return_url=settings.YOUR_DOMAIN + "settings/",
    )

    # Gebe die URL der Session zurück
    return Response({'url': f'{session.url}'}, status=200)



@api_view(['POST'])
def payment_session(request):
    print(request.user.id)

    stripe.api_key = settings.STRIPE_PRIVATE_KEY
    if stripe.api_key == "":
        try:
            Kunde = registrationModelData.objects.get(userid=request.user.id)
            if request.data['abo'] == "basic":
                Kunde.subvalue = 1
                Kunde.save()
                return Response({'url: ': f'{settings.YOUR_DOMAIN}dashboard'})
            elif request.data['abo'] == "premium":
                Kunde.subvalue = 2
                Kunde.save()
                return Response({'url: ': f'{settings.YOUR_DOMAIN}dashboard'})
        except Exception as e:
            return HttpResponse(str(e))
    else:
        print("12334")
        print(request.data['abo'])
        try:
            Kunde = registrationModelData.objects.get(userid=request.user.id)
            Kundenadresse = companyData.objects.get(userid=request.user.id)
            print(str(request.user))
            if not Kunde.stripe_customer_id:
                try:
                    customer = stripe.Customer.create(
                        email=request.user.email,
                        name=request.user.first_name + " " + request.user.last_name,

                        address={
                            "city": Kundenadresse.ort,
                            "postal_code": Kundenadresse.postleitzahl,
                            "line1": Kundenadresse.street,

                            #"country": "DE"  # Zweibuchstabiger Ländercode
                        },
                        metadata={
                            'user_id': str(request.user.id),
                            'username': request.user.username,
                            # Sie können hier weitere Schlüssel-Wert-Paare hinzufügen, je nachdem, was Sie speichern möchten
                        }
                    )

                    Kunde.stripe_customer_id = customer.id
                    Kunde.save()
                except stripe.error.StripeError as e:
                    # Behandlung von Stripe-spezifischen Fehlern
                    print("Stripe Error:", e)
                except Exception as e:
                    # Behandlung anderer Fehler
                    print("General Error:", e)

            subscriptions = stripe.Subscription.list(customer=Kunde.stripe_customer_id)
            active_subscriptions = [
                sub for sub in subscriptions.auto_paging_iter() if sub.status == 'active'
            ]

            active_price_ids = []
            for sub in active_subscriptions:
                for item in sub['items']['data']:
                    active_price_ids.append(item['price']['id'])

            if active_price_ids:
                print("Aktive Price IDs:", active_price_ids)
                # Hier können Sie Logik hinzufügen, um zu handeln, wenn ein aktives Abo gefunden wurde
                # Zum Beispiel können Sie überprüfen, ob eine bestimmte Price ID in der Liste ist
                if settings.stripe_basic_id in active_price_ids:
                    Kunde.subvalue = 1
                    Kunde.save()
                    return Response({'url': f'{settings.YOUR_DOMAIN}dashboard'})
                elif settings.stripe_premium_id in active_price_ids:
                    Kunde.subvalue = 2
                    Kunde.save()
                    return Response({'url': f'{settings.YOUR_DOMAIN}dashboard'})
               # print("ABC")
            if str(request.data['abo']) == "basic":
                print("Basic Buchung")
                checkout_session = stripe.checkout.Session.create(
                    metadata={'customer': request.user.id},
                    customer=Kunde.stripe_customer_id,
                    line_items=[
                        {

                            # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                            'price': settings.stripe_basic_id,
                            'quantity': 1,

                        },

                    ],
                    allow_promotion_codes=True,
                    mode='subscription',  # or 'payment', 'subscription', 'subscription'
                    success_url=settings.YOUR_DOMAIN + 'dashboard',  # onsuccess
                    cancel_url=settings.YOUR_DOMAIN + 'subscription',  # on cancel
                )

                print(checkout_session)
                return Response({'url': f'{checkout_session.url}'}, status=200)
            elif request.data['abo'] == "premium":
                checkout_session = stripe.checkout.Session.create(
                    metadata={'customer': request.user.id},
                    customer=Kunde.stripe_customer_id,
                    line_items=[
                        {

                            # Provide the exact Price ID (for example, pr_1234) of the product you want to sell
                            'price': settings.stripe_premium_id,
                            'quantity': 1,

                        },

                    ],
                    allow_promotion_codes=True,
                    mode='subscription',  # or 'payment', 'subscription', 'subscription'
                    success_url=settings.YOUR_DOMAIN + 'dashboard',  # onsuccess
                    cancel_url=settings.YOUR_DOMAIN + 'subscription',  # on cancel
                )

                print(checkout_session)
                return Response({'url': f'{checkout_session.url}'}, status=200)
        except Exception as e:

            return HttpResponse(str(e))


#######################################################################################################

def mailNotifierThread(request):
    global mailNotifier
    while mailNotifier == True:
        print("MailNotifierThread started")
        abo = Abo.objects.all()
        for abos in abo:
            if mailNotifier == True:
                companydata = companyData.objects.get(id=abos.besitzer)
                if companydata.mailnotification == True:
                    if abos.status == 1:
                        user = User.objects.get(id=abos.besitzer)
                        print(user.email)

                        print(abos.id)
                        print(abos.besitzer)
                        print(abos.abrechnungsdatum)
                        print("rechnungsid:" + str(abos.rechnungsintervall.interval))

                        current_date = timezone.localdate()

                        subscription_info = {
                            "date": abos.abrechnungsdatum.strftime('%Y-%m-%d'),
                            "interval": str(abos.rechnungsintervall.interval)
                        }

                        # Determine billing status using the datetime object
                        billing_status = is_billing_day(subscription_info, current_date)
                        print(billing_status)
                        if billing_status == True:
                            email_content = (f'<!DOCTYPE html>'
                                             f' <html> '
                                             f' <head> </head>'
                                             f'<body style="background-color: white; padding: 20%">'
                                             f'<div style="background-color: #F5F5F5; padding: 30px; height: 400px; align-items: center;">'
                                             f'<img src="/api/Logo-Voll.svg">'
                                             f'<h1 style="display: flex; justify-content: center; margin-bottom: 30px;">Abrechnung zu Ihrem Vertrag {abos.name}</h1>'
                                             f'<p style="display: flex; justify-content: center;">'
                                             f'Guten Tag {user.first_name} {user.last_name},'
                                             f'<br>'
                                             f'<br>'
                                             f'wir möchten Sie daran erinnern, dass die Abrechnung in höhe von {abos.preis} zu Ihrem Vertrag {abos.name} am {abos.abrechnungsdatum} ansteht.'
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
                                             f'<html>')
                            send_mail_method('AboSync Payment reminder',f'Achtung die Zahlung bei {abos.name} läuft morgen an. Prüfen sie ob ihr Konto ausreichend gedeckt ist.{abos.preis}€ werden abgebucht.',email_content,str(user.email))
                           # send_mail(
                         #       'AboSync Payment reminder',
                         ##       f'Achtung die Zahlung bei {abos.name} läuft morgen an. Prüfen sie ob ihr Konto ausreichend gedeckt ist.{abos.preis}€ werden abgebucht.',
                          #      'support@abosync.com',  # Absender
                          #      [str(user.email)],  # Empfänger
                          #      fail_silently=False,
                          #      html_message=email_content
                          #  )

        time.sleep(10)

    # send_mail('AboSync: Abo läuft bald ab')

    print("MailNotifierThread stopped")
    mailNotifier = False


# Given data


# Function to determine if today is a billing day based on the subscription info
def is_billing_day(subscription, current_date):
    # Parse the date from the string
    start_date = datetime.strptime(subscription['date'], "%Y-%m-%d")
    # Calculate the difference in months
    month_diff = (current_date.year - start_date.year) * 12 + current_date.month - start_date.month

    # Determine the billing interval
    if subscription['interval'] == "1":
        interval = 1
    elif subscription['interval'] == "3":
        interval = 3
    elif subscription['interval'] == "6":
        interval = 6
    elif subscription['interval'] == "12":
        interval = 12
    else:
        # Unknown interval
        return False
    # Check if the current day is a billing day
    return month_diff % interval == 0 and current_date.day == start_date.day - 1


@api_view(['GET'])
def getMailNotifier(request):
    if request.user.is_staff:
        # Variablen zum Speichern des Status des MailNotifier-Threads
        mailNotifierRunning = False

        for thread in threading.enumerate():
            print("+++ " + str(thread.getName()))
            if thread.getName() == "MailNotifier":
                print("MailNotifier is alive:", thread.is_alive())
                mailNotifierRunning = True
                break  # Verlassen der Schleife, wenn der Thread gefunden wurde

        # Entscheidung auf Basis des MailNotifier-Status
        if mailNotifierRunning:
            return Response({'status': 'MailNotifier already running'}, status=200)
        else:
            print("MailNotifier is not alive")
            return Response({'status': 'MailNotifier not running'}, status=200)
    else:
        return Response(status=403)


@api_view(['GET'])
def getStaff(request):
    print(request.user)
    if request.user.is_authenticated:
        if request.user.is_staff:
            return Response({'message': True}, status=200)
        return Response({'message': False}, status=200)
    else:
        return Response(status=403)




class PasswordForgot(APIView):
    parser_classes = [JSONParser]

    def post(self, request):
        # Accessing the email from request data
        email = request.data.get('email')

        # Überprüfen, ob ein Benutzer mit dieser E-Mail existiert
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'error': 'Kein Benutzer mit dieser E-Mail gefunden'})

        # Token und uid generieren
        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        #cd current_site = "localhost:4200"

        # Link für das Zurücksetzen des Passworts
        link = f'{settings.YOUR_DOMAIN}reset-password/{uid}/{token}'

        email_content = (f'<!DOCTYPE html>'
                         f' <html> '
                         f' <head> </head>'
                         f'<body style="background-color: white; padding: 20%">'
                         f'<div style="background-color: #F5F5F5; padding: 30px; height: 400px; align-items: center;">'
                         f'<img src="/api/Logo-Voll.svg">'
                         f'<h1 style="display: flex; justify-content: center; margin-bottom: 30px;">AboSync</h1>'
                         f'<p style="display: flex; justify-content: center;">'
                         f'Guten Tag {user.first_name} {user.last_name},'
                         f'<br>'
                         f'<br>'
                         f'Bitte benutzen Sie folgenden Link, um Ihr Passwort zurückzusetzen: {link}.'
                         f'<br>'
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
                         f'<html>')
        print(link)
        send_mail_method('AboSync Passwort zurücksetzen',f'Bitte benutzen Sie folgenden Link, um Ihr Passwort zurückzusetzen: {link}', email_content,[email] )
       # send_mail(
       #     'AboSync Passwort zurücksetzen',
       #     f'Bitte benutzen Sie folgenden Link, um Ihr Passwort zurückzusetzen: {link}',
       #     'support@abosync.com',  # Absender
        #    [email],  # Empfänger
        #    fail_silently=False,
        #    html_message=email_content
        #)



        return Response({'success': 'E-Mail zum Zurücksetzen des Passworts gesendet'})


@api_view(['GET'])
def get_this_month_billing_subscriptions(request):
    if request.user.is_authenticated:
        try:
            all_abos = Abo.objects.filter(besitzer=request.user.id)
            current_date = datetime.now()
            due_this_month = []

            for abo in all_abos:
                output = is_billing_month(abo, current_date)
                if output is not None:
                    due_this_month.append({
                        "name": abo.name,
                        "preis": abo.preis,
                        "abrechnungsdatum": abo.abrechnungsdatum,
                        "status": output
                    })

                    # Convert due_this_month into a serializable format if necessary, like a list of IDs or a serialized queryset
            # Depending on your needs, you might return a Response with a JSON body
            return Response(due_this_month)
        except Abo.DoesNotExist:
            return Response(status=404)
    else:
        return Response(status=403)







@api_view(['POST'])
@permission_classes([AllowAny])
def resetforgottenpassword(request):
    uidb64 = request.data.get('uid')
    token = request.data.get('token')
    new_password = request.data.get('new_password')

    try:
        # Decode the uid
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        print(token)
        # Check the token and set new password
        if default_token_generator.check_token(user, token):
            user.set_password(new_password)
            user.save()
            return Response({'success': 'Password has been reset'})
        else:
            return Response({'error': 'Invalid token'}, status=400)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        print(token)
        return Response({'error': 'Invalid request'}, status=400)


@api_view(['POST'])
def deleteAccount(request):
    # Der authentifizierte Benutzer ist der, der gelöscht werden soll
    if request.user.is_authenticated:
        try:
            # Alle Abonnements des Benutzers löschen
            response = delete_stripe_account(request)
            print(response)
            try:
                ImageModel.objects.filter(owner=request.user.id).delete()
                print("images deleted")
            except:
                print("no models in images left")
            try:
                Abo.objects.filter(besitzer=request.user.id).delete()
                print("abos deleted")
            except:
                print("no models in abos left")
            try:
                companyData.objects.filter(userid=request.user.id).delete()
                print("companydata deleted")
            except:
                print("no models in companydata left")
            # Benutzer aus der Datenbank löschen
            try:
                EmailCode.objects.filter(userid=request.user.id).delete()
                print("emailcode deleted")
            except:
                print("no models in emailcode left")

            try:
                registrationModelData.objects.filter(userid=request.user.id).delete()
                print("registrationmodeldata deleted")
            except:
                print("no models in registrationmodeldata left")
            # Benutzer aus der Datenbank löschen
            request.user.delete()

            return Response({"message": "User account successfully deleted."}, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"message": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            # Fange alle anderen möglichen Fehler ab
            print(str(e))
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


    else:
        return Response({"message": "no"}, status=404)



@api_view(['GET'])
def resendVerificationMail(request):
    if request.user.is_authenticated:
        try:
            mailcode = EmailCode.objects.get(userid=request.user.id)
            print("teste12553")
            print(request.user.id)
            print(mailcode.emailcode)
            email_content = (f'<!DOCTYPE html>'
                             f' <html> '
                             f' <head> </head>'
                             f'<body style="background-color: white; padding: 20%">'
                             f'<div style="background-color: #F5F5F5; padding: 30px; height: 400px; align-items: center;">'
                             f'<img src="/api/Logo-Voll.svg">'
                             f'<h1 style="display: flex; justify-content: center; margin-bottom: 30px;">AboSync</h1>'
                             f'<p style="display: flex; justify-content: center;">'
                             f'Guten Tag {request.user.first_name} {request.user.last_name},'
                             f'<br>'
                             f'<br>'
                             f'Wir senden Ihnen erneut Ihren Verifizierungscode: {mailcode.emailcode}.<br>'
                             f'Ihr AboSync Benutzername ist: {request.user.username}'
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
                             f'<html>')
            print(email_content)

            send_mail_method('Dein Verifizierungscode für AboSync', f'Der Verifizierungscode lautet: {mailcode.emailcode}',email_content, request.user.email)



        except:
            print("1454165")
        return Response(status=200)
    else:
        return Response(status=404)


