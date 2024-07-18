from django.contrib import admin
from .models import AddressIP, Session, PasswordResetToken, ValidEmailToken

admin.site.register(AddressIP)
admin.site.register(PasswordResetToken)
admin.site.register(ValidEmailToken)

@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = ('user_id', 'address_id', 'consultation_date')
    search_fields = ('user_id__username', 'address_id__address_ip')
    ordering = ('-consultation_date',)
