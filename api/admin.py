from django.contrib import admin

from api.models import registrationModelData, EmailCode, companyData


# Register your models here.
admin.site.register(registrationModelData)
admin.site.register(EmailCode)
admin.site.register(companyData)