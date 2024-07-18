from rest_framework import serializers

# own imports
from .models import User

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for the User model.
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'password']
        extra_kwargs = {'password': {'write_only': True, 'required': False}}
    
    def create(self, validated_data):
        """
        Creates a new user instance.
        """
        user = User(**validated_data)
        user.set_password(validated_data['password'])
        user.save()
        return user
    
    def update(self, instance, validated_data):
        """
        Updates an existing user instance.
        """
        allowed_fields = ['username', 'email', 'first_name', 'last_name']
        for field in validated_data:
            if field not in allowed_fields:
                raise serializers.ValidationError({'error': f"Cannot update field '{field}'"})
        for field in allowed_fields:
            if field in validated_data:
                setattr(instance, field, validated_data[field])
        instance.save()
        return instance
    
    def validate(self, data):
        """
        Validates the input data.
        """
        email = data.get('email')
        username = data.get('username')
        
        if email:
            if User.objects.filter(email=email).exclude(id=self.instance.id if self.instance else None).first():
                raise serializers.ValidationError({'email': 'Email already exists'})
        
        if username:
            if User.objects.filter(username=username).exclude(id=self.instance.id if self.instance else None).first():
                raise serializers.ValidationError({'username': 'Username already exists'})
        
        return data