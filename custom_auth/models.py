from django.db import models

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


class Session (models.Model):
    
    user_id = models.ForeignKey(User, on_delete=models.CASCADE)
    address_id = models.ForeignKey(AddressIP, on_delete=models.CASCADE)
    consultation_date = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        
        return f'{self.user_id.username} - {self.address_id.address_ip} - {self.consultation_date}'

    class Meta:
        """
        Metadata for the AddressIP model.
        """
        db_table = 'server_session'  # Table name in the database
        verbose_name = 'session'
        verbose_name_plural = 'sessions'  # corrected plural form
