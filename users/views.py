import string
import secrets
from datetime import datetime
from rest_framework.decorators import api_view

# respose
from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework import status

# auth
import jwt
from rest_framework.decorators import  permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser

# send email
from django.conf import settings
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.template.loader import render_to_string

# own imports
from .serializers import UserSerializer
from .models import User, PasswordResetToken, ValidEmailToken
from custom_auth.models import Session

############# functions to help APIs #############

# create a random token
def create_token(model) -> str:
    
    characters: str = string.ascii_lowercase + string.digits + string.ascii_uppercase
    
    while True:
        
        tokens = ["".join(secrets.choice(characters) for _ in range(6)) for _ in range(6)]
        token = "-".join(tokens)
        
        if model.objects.filter(token=token).count() == 0:
            return token

####################################################

############# APIs #############

# create user, only the superadmin can create users
@api_view(['POST'])
@permission_classes([IsAdminUser])
def create_user(request):
    
    serializer = UserSerializer(data=request.data)

    if serializer.is_valid():
        
        user = serializer.save(serializer.validated_data)

        response_data = {
            'user_id': user.id,
        }
        
        return Response(response_data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Send an email to the user that the admin created so that they can log in and confirm that their email is valid
@api_view(['POST'])
@permission_classes([IsAdminUser])
def send_validation_emial(request, id):
    
    user = User.objects.filter(id=id)
    
    if user.exists():
        
        user = user.first()
    
        token = create_token(model= ValidEmailToken)
        # we generate the token to validate the email
        ValidEmailToken.objects.create(user_id=user.id, token=token)
        
        # Send an email to the user to confirm their email address
        context = {
            'user': user,
            'change_password_url': f'http://127.0.0.1:8000/validate_email/{token}/',
            'year': datetime.now().year
        }
        
        html_content = render_to_string('emails/valid_emial.html', context)
        plain_message = strip_tags(html_content)
        
        send_mail(
            subject='Verify Your Email',
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_content
        )

        return Response({'message': 'The email has been sent to the user'}, status= status.HTTP_200_OK)
        
    else:
        
        return Response({'error': 'Invalid token'}, status=status.HTTP_404_NOT_FOUND)


# validates the user account and changes its status from is_active to true
@api_view(['POST'])
@permission_classes([AllowAny])
def validate_email(request, token = None):

    if not token:
        return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        email_token = ValidEmailToken.objects.get(token=token)
        if email_token.is_expired():
            # we remove the token since it cannot be used
            email_token.delete() 
            return Response({'error': 'Token has expired'}, status=status.HTTP_400_BAD_REQUEST)

        user = email_token.user
        user.is_active = True
        user.save()
        email_token.delete()

        #3
        # Sends an email to the user to notify them that their email has been validated
        context = {
            'user': user,
            'year': datetime.now().year
        }
        
        html_content = render_to_string('emails/valid_password_notification.html', context)
        plain_message = strip_tags(html_content)
        
        send_mail(
            subject='Account Validated successfully!',
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_content
        )
        
        return Response({'message': 'validated email'}, status=status.HTTP_200_OK)

    except ValidEmailToken.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)


# get user information
@api_view(['GET'])
def get_myself(request):
    
    token = request.META.get('HTTP_AUTHORIZATION').split()[1]
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        user_exists = User.objects.filter(id=user_id)
        
        if not user_exists.exists():
            return Response({'user_id': f'the user with the id {user_id} does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = user_exists.first()
        
        result = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
        }
        
        return Response(result, status=status.HTTP_202_ACCEPTED)
        
    except jwt.exceptions.InvalidTokenError:
        return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


# Send the email with the token to change the password
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request(request):
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

    token = create_token(model= PasswordResetToken)
    # Generate password reset token
    PasswordResetToken.objects.create(user_id=user.id, token=token)

    #3
    # Send email to the user with the token to change the password
    context = {
        'user': user,
        'change_password_url': f'http://example.com/change-password/{token}',
        'year': datetime.now().year
    }
    
    html_content = render_to_string('emails/change_password_email.html', context)
    plain_message = strip_tags(html_content)
    
    send_mail(
        subject='Change Password',
        message=plain_message,
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[user.email],
        html_message=html_content
    )

    return Response({'message': 'Password reset instructions have been sent to your email'}, status=status.HTTP_200_OK)


# allows you to change the password with the token that was sent by email
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset(request, token):
    
    password = request.data.get('new_password')
    confirn_password = request.data.get('confirn_password')

    if not confirn_password or not password:
        return Response({'error': 'Token and password are required'}, status=status.HTTP_400_BAD_REQUEST)

    if password != confirn_password:
        return Response({'pasword': 'the keys are not the same'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        reset_token = PasswordResetToken.objects.get(token=token)
        if reset_token.is_expired():
            return Response({'error': 'Token has expired'}, status=status.HTTP_400_BAD_REQUEST)

        user = reset_token.user
        user.set_password(password)
        user.save()
        reset_token.delete()

        #3
        # sends an email to notify the user that the password has been changed
        context = {
            'user': user,
            'year': datetime.now().year
        }
        
        html_content = render_to_string('emails/password_changed_notification.html', context)
        plain_message = strip_tags(html_content)
        
        send_mail(
            subject='Password Changed successfully!',
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_content
        )

        
        return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)

    except PasswordResetToken.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_user(request, id = None, sessions = False):
    
    if not id:
        return Response({'id':'you have to enter the user id'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=id)
        sessions_user = Session.objects.filter(user_id=id)
    except User.DoesNotExist:
        return Response({'error': 'Username does not exist'}, status=status.HTTP_404_NOT_FOUND) 
    
    result = {
        'user_id': user.id,
        'username': user.username,
        'email': user.email
    }
    
    if sessions:
        
        result['sessions'] = []
        
        if sessions_user.exists():
        
            for session in sessions_user:
                
                result['sessions'].append(
                    {
                        'address_ip': session.address_id,
                        'consultation_date': session.consultation_date
                    }
                )
    
    return Response(result, status=status.HTTP_202_ACCEPTED)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def list_users(request, sessions = False):
    
    users = User.objects.all()
    
    result = []
    
    for user in users:
        
        data = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email
        }
    
        if sessions:
            
            sessions_user = Session.objects.filter(user_id=id)
            
            data['sessions'] = []
            
            if sessions_user.exists():
            
                for session in sessions_user:
                    
                    data['sessions'].append(
                        {
                            'address_ip': session.address_id,
                            'consultation_date': session.consultation_date
                        }
                    )
        
        result.append(data)
    
    return Response(result, status=status.HTTP_202_ACCEPTED)


@api_view(['PUT'])
def update_user(request, id):
    
    token = request.META.get('HTTP_AUTHORIZATION').split()[1]

    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    user_id = payload['user_id']
    user = User.objects.filter(id=user_id)
    
    if not user.exists():
        return Response({'user_id': f'the user with the id {user_id} does not exist'}, status=status.HTTP_404_NOT_FOUND)
    
    if not user.id == id or not user.is_superuser:
        return Response({'error': f'You do not have permissions to update this user'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)
    
    #3
    pass

@api_view(['POST'])
@permission_classes([IsAdminUser])
def block_user(request, id):
    
    try:
        user = User.objects.get(id=id)
        user.is_active = False
        user.save()
        
        return Response({'message': 'the user has been blocked'}, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({'error': 'Username does not exist'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_user(request, id):
    
    try:
        user = User.objects.get(id=id)
        user.delete()
        
        return Response({'message': 'the user has been delete'}, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({'error': 'Username does not exist'}, status=status.HTTP_404_NOT_FOUND)

##########################