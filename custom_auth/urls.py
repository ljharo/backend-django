from django.urls import path
from rest_framework_simplejwt.views import (
    TokenRefreshView, 
    TokenBlacklistView)

# own imports
from . import views


urlpatterns = [
    
    path('login/', views.login, name='login'),
    path('logout/', TokenBlacklistView.as_view(), name='logout'),
    
    path('token/validate/access', views.valid_token, name='validate_token'),
    # path('token/validate/refresh', views.valid_token, name='validate_token'),
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh_token'),
    
    path('session/<int:user_id>', views.get_session, name='get_session')
]