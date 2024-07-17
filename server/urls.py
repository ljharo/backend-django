from django.urls import path, include
from django.contrib import admin

urlpatterns = [
    
    path('admin/', admin.site.urls),
    path('users/' ,include('users.urls'), name='users'),
    path('auth/' ,include('custom_auth.urls'), name='auth'),
    
]
