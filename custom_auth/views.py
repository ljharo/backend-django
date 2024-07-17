from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.shortcuts import get_object_or_404


# auth
import jwt
from rest_framework.decorators import  permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from rest_framework_simplejwt.tokens import AccessToken

# own imports
from users.models import User
from .models import AddressIP, Session

############# functions to help APIs #############

# register logins
def register_session(request, user)  -> str:

    address_ip = AddressIP.objects.get_or_create(address_ip=request.META['REMOTE_ADDR'])
    session = Session(user_id=user, address_id=address_ip[0])
    session.save()
    
    return session.id

##########################

############# APIs #############

# login user
@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    
    # searching username or email to search database
    if request.data.get('username'):
        user = get_object_or_404(User, username=request.data['username'])
    elif request.data.get('email'):
        user = get_object_or_404(User, email=request.data['email'])
    else:
        return Response({'error': 'you have to enter the username or email'}, status=status.HTTP_400_BAD_REQUEST)

    # valid password
    if not user.check_password(request.data['password']):
        return Response({'error': 'Invalid password'}, status=status.HTTP_400_BAD_REQUEST)

    #3 It is necessary to validate that the user already has an active session and return this instead of creating a new one
    access_token = AccessToken.for_user(user)
    refresh_token = RefreshToken.for_user(user)
    result = {
        'access_token': str(access_token),
        'efresh_token': str(refresh_token),
        'essage': 'permission granted'
    }

    register_session(request, user)
    return Response(result, status=status.HTTP_202_ACCEPTED)

# validate if the access token is still valid
@api_view(['GET'])
def valid_token(request):
    return Response({}, status=status.HTTP_200_OK)

# get user logins
@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_session(request, id):
    
    user = get_object_or_404(User, id=id)
    
    sessions = Session.objects.filter(user_id=user.id)
    
    if sessions.exists():
        
        result = []
        for value in sessions.all():
            
            result.append(
                {
                    'session_id': value.id,
                    'user_id': value.user_id.id,
                    'username': value.user_id.username,
                    'ip_adress': value.address_id.address_ip,
                    "registration_date": value.consultation_date
                }
            )
        
        return  Response(result, status=status.HTTP_200_OK)
    
    return Response(status=status.HTTP_204_NO_CONTENT)

##########################

