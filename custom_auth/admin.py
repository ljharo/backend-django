from django.contrib import admin
from .models import AddressIP, Session

admin.site.register(AddressIP)

@admin.register(Session)
class SessionAdmin(admin.ModelAdmin):
    list_display = ('user_id', 'address_id', 'consultation_date')
    search_fields = ('user_id__username', 'address_id__address_ip')
    ordering = ('-consultation_date',)
