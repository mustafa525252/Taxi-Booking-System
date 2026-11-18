from django.contrib import admin
from .models import CustomerProfile, AdminAccount, AdminPasswordResetOTP

# Register your models here.

#Let's register an CustomerProfile model to the admin site
admin.site.register(CustomerProfile)
admin.site.register(AdminAccount)
admin.site.register(AdminPasswordResetOTP)
