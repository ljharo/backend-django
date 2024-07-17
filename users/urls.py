from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView, TokenBlacklistView

# own imports
from . import views

urlpatterns = [

    ########### User ###########
    path('create/', views.create_user, name='create_user'),
    path('get/myself/', views.get_myself, name='get_myself'),
    path('get/<int:id>/<int:session>/', views.get_user, name='get_user'),
    path('get/list/<int:session>/', views.list_users, name='list_users'),
    path('update/<int:id>/', views.update_user, name='update_user'),
    path('block/<int:id>/', views.block_user, name='block_user'),
    path('delete/<int:id>/', views.delete_user, name='delete_user'),
    ######################
    
    ########### validate email ###########
    path('eamil/send_validation/', views.send_validation_emial, name='resend_email_validation'),
    path('emial/validate/<str:token>/', views.validate_email, name='validate_email'),
    ######################
    
    ########### change password ###########
    path('password/reset_request/', views.password_reset_request, name='reset_password'),
    path('password/reset/<str:token>', views.password_reset, name='password_reset')
    ######################
]
