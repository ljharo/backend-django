from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    """
    Custom User model that inherits from Django's AbstractUser.
    """
    is_validated = models.BooleanField(default=False)
    
    def __str__(self):
        """
        Returns a string representation of the user.
        """
        return f"{self.username}"
    
    class Meta:
        """
        Metadata for the User model.
        """
        db_table = 'users'  # Table name in the database
        verbose_name = 'user'
        verbose_name_plural = 'users'