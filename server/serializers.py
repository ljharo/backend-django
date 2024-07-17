from rest_framework import serializers
from django.contrib.auth.models import User

class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password']
    
    def save(self, validated_data):
        
        user = User(**validated_data)
        
        # the user has to validate their email
        user.is_active = False
        
        user.set_password(user.password)
        user.save()
        
        return user
    
    def validate(self, data):

        if email:= data.get('email'):
            if User.objects.filter(email=email).first():
                raise serializers.ValidationError({'error':'Email already exists'})
        
        return data