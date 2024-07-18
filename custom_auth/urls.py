from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView

# own imports
from . import views

urlpatterns = [
    # Authentication
    path('login/', views.login, name='login'),
    path('logout/', TokenBlacklistView.as_view(), name='logout'),
    
    # Token validation and refresh
    path('token/validate/access', views.validate_token_access, name='validate_token_access'),
    path('token/validate/refresh', views.validate_token_refresh, name='validate_token_refresh'),
    path('token/refresh/', TokenRefreshView.as_view(), name='refresh_token'),
    
    # Session management
    path('session/<int:user_id>', views.get_sessions, name='get_session'),
    
    # Email validation
    path('email/send_validation/', views.send_validation_email, name='resend_email_validation'),
    path('email/validate/<str:token>/', views.validate_email, name='validate_email'),
    
    # Password reset
    path('password/reset_request/', views.password_reset_request, name='reset_password_request'),
    path('password/reset/<str:token>', views.password_reset, name='password_reset'),
]