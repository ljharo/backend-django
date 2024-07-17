from django.contrib import admin
from .models import  PasswordResetToken, ValidEmailToken

admin.site.register(PasswordResetToken)
admin.site.register(ValidEmailToken)