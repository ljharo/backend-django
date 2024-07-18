from django.urls import path

# own imports
from . import views

urlpatterns = [
    ########### User ###########
    # Create a new user
    path('create/', views.create_user, name='create_user'),
    
    # Get the current user's information
    path('get/myself/', views.get_myself, name='get_myself'),
    
    # Get a user's information by ID and session
    path('get/<int:id>/<int:session>/', views.get_user, name='get_user'),
    
    # Get a list of users for a given session
    path('get/list/<int:session>/', views.list_users, name='list_users'),
    
    # Update a user's information
    path('update/<int:id>/', views.update_user, name='update_user'),
    
    # Block a user
    path('block/<int:id>/', views.block_user, name='block_user'),
    
    # Unlock a user
    path('unlock/<int:id>', views.unlock_user, name='unlock_user'),
    
    # Delete a user
    path('delete/<int:id>/', views.delete_user, name='delete_user'),
    
    # Make a user an admin
    path('make/admin/<int:id>/', views.make_admin, name='make_admin'),
    
    # Make a user a staff member
    path('make/staff/<int:id>', views.make_staff, name='make_staff'),
    ######################
]