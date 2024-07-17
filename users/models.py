from django.db import models
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth.models import AbstractUser



class User (AbstractUser):
    
    is_block = models.BooleanField(default=False)


class PasswordResetToken(models.Model):
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=(timezone.now() + timedelta(days=1)))

    def is_expired(self):
        return self.expires_at < timezone.now()
    
    def __str__(self):
        return f"{self.user.username} {self.token} {self.expires_at}"
    
    class Meta:
        """
        Metadata for the AddressIP model.
        """
        db_table = 'user_passwor_reset_token'  # Table name in the database
        verbose_name = 'passwor reset token'
        verbose_name_plural = 'passwor reset tokens'  # corrected plural form


class ValidEmailToken(models.Model):
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=(timezone.now() + timedelta(days=1)))

    def is_expired(self):
        return self.expires_at < timezone.now()
    
    def __str__(self):
        return f"{self.user.username} {self.token} {self.expires_at}"
    
    class Meta:
        """
        Metadata for the AddressIP model.
        """
        db_table = 'user_valid_email_token'  # Table name in the database
        verbose_name = 'valid email token'
        verbose_name_plural = 'valid email tokens'  # corrected plural form