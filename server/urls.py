from django.urls import path, include
from django.contrib import admin

urlpatterns = [
    
    # Admin interface
    path('admin/', admin.site.urls),
    
    # User management URLs
    path('users/' ,include('users.urls'), name='users'),
    
    # Custom authentication URLs
    path('auth/' ,include('custom_auth.urls'), name='auth'),
    
]