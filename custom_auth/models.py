from django.db import models
from datetime import timedelta
from django.utils import timezone

# own imports
from users.models import User


class AddressIP (models.Model):
    """
    Represents an IP address with a unique address and a status flag.
    """

    # Unique IP address.
    address_ip = models.CharField(max_length=20, blank=False, null=False, unique=True)

    # Status flag indicating whether the IP address is active or not.
    status = models.BooleanField(default=True)

    def __str__(self):
        """
        Returns a human-readable representation of the IP address.

        :return: The IP address as a string.
        """
        return self.address_ip

    class Meta:
        """
        Metadata for the AddressIP model.
        """
        db_table = 'server_address_ip'  # Table name in the database
        verbose_name = 'address IP'
        verbose_name_plural = 'address IPs'  # corrected plural form


class Session(models.Model):
    """
    Represents a user session with an associated IP address and consultation date.
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address = models.ForeignKey(AddressIP, on_delete=models.CASCADE)
    consultation_date = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """
        Returns a human-readable representation of the session.

        Returns:
            str: A string representing the session, including the user, IP address, and consultation date.
        """
        return f'{self.user.username} - {self.address.address_ip} - {self.consultation_date}'

    class Meta:
        """
        Metadata for the Session model.
        """
        db_table = 'server_session'  # Table name in the database
        verbose_name = 'session'
        verbose_name_plural = 'sessions'


class PasswordResetToken(models.Model):
    """
    Represents a password reset token.

    This model stores information about a password reset token associated with a user.

    Attributes:
        user (User): User associated with the token
        token (str): Unique token
        created_at (datetime): Token creation date and time
        expires_at (datetime): Token expiration date and time
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=(timezone.now() + timedelta(days=1)))

    def is_expired(self) -> bool:
        """
        Checks if the token has expired.

        Returns:
            bool: True if the token has expired, False otherwise
        """
        return self.expires_at < timezone.now()

    def __str__(self) -> str:
        """
        String representation of the token.

        Returns:
            str: A string representing the token, including the user and expiration date
        """
        return f"{self.user.username} {self.token} {self.expires_at}"

    class Meta:
        """
        Metadata for the PasswordResetToken model.

        Attributes:
            db_table (str): Table name in the database
            verbose_name (str): Verbose name of the model
            verbose_name_plural (str): Verbose plural name of the model
        """
        db_table = 'user_password_reset_token'  # corrected table name
        verbose_name = 'password reset token'
        verbose_name_plural = 'password reset tokens'  # corrected plural form


class ValidEmailToken(models.Model):
    """
    Represents a valid email token.

    This model stores information about a valid email token associated with a user.

    Attributes:
        user (User): User associated with the token
        token (str): Unique token
        created_at (datetime): Token creation date and time
        expires_at (datetime): Token expiration date and time
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=(timezone.now() + timedelta(days=1)))

    def is_expired(self) -> bool:
        """
        Checks if the token has expired.

        Returns:
            bool: True if the token has expired, False otherwise
        """
        return self.expires_at < timezone.now()

    def __str__(self) -> str:
        """
        String representation of the token.

        Returns:
            str: A string representing the token, including the user and expiration date
        """
        return f"{self.user.username} {self.token} {self.expires_at}"

    class Meta:
        """
        Metadata for the ValidEmailToken model.

        Attributes:
            db_table (str): Table name in the database
            verbose_name (str): Verbose name of the model
            verbose_name_plural (str): Verbose plural name of the model
        """
        db_table = 'user_valid_email_token'  # Table name in the database
        verbose_name = 'valid email token'
        verbose_name_plural = 'valid email tokens'  # corrected plural form