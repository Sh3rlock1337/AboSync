# api/urls.py

from django.urls import path

from . import views
from .views import LoginView, LogoutView, get_logged_in_user, UserProfileCreateView, CompanyDataDetailView, \
    RegistrationModelDataListCreateView, RegistrationModelDataRetrieveUpdateDeleteView, ImageRetrieveView, \
    ImageUploadView, PasswordForgot
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView





urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('logged-in-user/', get_logged_in_user, name='logged_in_user'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', UserProfileCreateView.as_view(), name='register'),
    path('company_data/<int:userid>/', CompanyDataDetailView.as_view(), name='company_data-detail'),
    path('registrationmodel/', RegistrationModelDataListCreateView.as_view(), name='registrationmodel-list'),
    path('registrationmodel/<int:userid>/', RegistrationModelDataRetrieveUpdateDeleteView.as_view(), name='registrationmodel-detail'),
    path('emailcodes/', views.emailcode_list, name='emailcode_list'),
    path('emailcodes/<int:pk>/', views.emailcode_detail, name='emailcode_detail'),
    path('resendmail/', views.resendVerificationMail, name='resendMail'),

    path('kategories/', views.kategories_list, name='item-list'),
    path('kategorie/<int:pk>/', views.kategorie_detail, name='item-detail'),
    path('billingintervals_list/', views.billingintervals_list, name='billing-list'),
    path('abolist/', views.abolist, name="pricing-list"),
    path('abo/<int:pk>/', views.aboget, name="pricing-list"),

    path('abopost/', views.abopost, name="pricing-list"),

    path('resetpassword/', views.resetpassword, name="resetpassword"),
    path('changeMailNotifier/', views.changeMailNotifier, name="changeMailNotifier"),

    path('setMailNotifier/', views.setMailNotifier, name="startMailNotifier"),
    path('getMailNotifier/', views.getMailNotifier, name="getMailNotifier"),

    path('getStaff/', views.getStaff, name="getStaff"),
    #IMAGES
    path('upload/', ImageUploadView.as_view(), name='image-upload'),
    path('image/<int:pk>/', ImageRetrieveView.as_view(), name='image-retrieve'),
    path('forgotpassword/', PasswordForgot.as_view(), name='forgotpassword'),
    path('resetforgottenpassword/', views.resetforgottenpassword, name='resetforgottenpassword'),
    path('getallAbos/', views.get_this_month_billing_subscriptions, name='getallAbos'),
    path('deleteAccount/', views.deleteAccount, name="delete"),


    path('stripemanager/', views.create_customer_portal_session, name="abomanager_session"),
    path('stripecheckout/', views.payment_session, name='payment_session'),
    path('stripe/webhook', views.stripe_webhook, name='stripe_webhook'),


    #{
 #   "name": "Netflix",
  #  "preis": 12.99,
   # "kategorie" : 1,
   # "rechnungsintervall": 1,
   # "abrechnungsdatum":"2023-07-12"
#}

]
