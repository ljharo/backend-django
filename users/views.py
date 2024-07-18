from django.conf import settings
from rest_framework.decorators import api_view

# respose
from rest_framework import status
from rest_framework.response import Response

# auth
import jwt
from rest_framework.decorators import  permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser

# own imports
from .models import User
from .serializers import UserSerializer
from custom_auth.models import Session


############# APIs #############

# create user, only the superadmin can create users
@api_view(['POST'])
@permission_classes([IsAdminUser])
def create_user(request):
    """
    Create a new user in the system. Only the superadmin has permission to create users.

    Parameters:
    request (HttpRequest): The HTTP request containing the user data to create.

    Returns:
    Response: An HTTP response object containing the created user's ID if the request is valid, or an error object if the request is not valid.
    """
    serializer = UserSerializer(data=request.data)

    if serializer.is_valid():
        user = serializer.save()
        response_data = {
            'user_id': user.id,
        }
        return Response(response_data, status=status.HTTP_201_CREATED)

    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def get_myself(request):
    """
    Retrieve the authenticated user's information.

    This view expects a valid JWT token in the Authorization header.
    It decodes the token, extracts the user ID, and returns the corresponding user's information.

    Args:
        request: The incoming request object.

    Returns:
        Response: A JSON response containing the user's information if the token is valid,
                or an error response if the token is invalid or the user does not exist.

    Raises:
        jwt.exceptions.InvalidTokenError: If the provided token is invalid.
    """
    # get user information
    token = request.META.get('HTTP_AUTHORIZATION').split()[1]
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        user_id = payload['user_id']
        
        try:
            user = User.objects.filter(id=user_id)
        except User.DoesNotExist:
            return Response({'error':'Username does not exist'}, status=status.HTTP_400_BAD_REQUEST)
        
        result = {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active': user.is_active,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser,
            'is_validated': user.is_validated
        }
        
        return Response(result, status=status.HTTP_202_ACCEPTED)
        
    except jwt.exceptions.InvalidTokenError:
        return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_user(request, id=None, sessions=False):
    """
    Retrieve a user's information by ID.

    This view is only accessible by admin users.
    It returns the user's basic information, and optionally, their session history.

    Args:
        request: The incoming request object.
        id (int): The ID of the user to retrieve. Required.
        sessions (bool): Whether to include the user's session history. Defaults to False.

    Returns:
        Response: A JSON response containing the user's information, and optionally, their session history.

    Raises:
        Http404: If the user with the specified ID does not exist.
    """
    if not id:
        return Response({'id': 'You have to enter the user ID'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(id=id)
        sessions_user = Session.objects.filter(user_id=id)
    except User.DoesNotExist:
        return Response({'error': 'Username does not exist'}, status=status.HTTP_404_NOT_FOUND) 
    
    result = {
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'is_active': user.is_active,
        'is_staff': user.is_staff,
        'is_superuser': user.is_superuser,
        'is_validated': user.is_validated
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
def list_users(request, sessions=False):
    """
    Retrieve a list of all users.

    This view is only accessible by admin users.
    It returns a list of users with their basic information, and optionally, their session history.

    Args:
        request: The incoming request object.
        sessions (bool): Whether to include the users' session history. Defaults to False.

    Returns:
        Response: A JSON response containing a list of users with their information, and optionally, their session history.
    """
    users = User.objects.all()
    
    result = [
        {
            'user_id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'sessions': [] if not sessions else [
                {
                    'address_ip': session.address_id,
                    'consultation_date': session.consultation_date
                } for session in Session.objects.filter(user_id=user.id)
            ]
        } for user in users
    ]
    
    return Response(result, status=status.HTTP_200_OK)


@api_view(['PUT'])
def update_user(request, id):
    """
    Update a user.

    This view allows an admin or the owner of the account to update a user.

    Args:
        request: The incoming request object.
        id (int): The ID of the user to update.

    Returns:
        Response: A JSON response indicating the result of the update operation.
    """
    token = request.META.get('HTTP_AUTHORIZATION').split()[1]
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    user_id = payload.get('user_id')

    try:
        user_asking_changes = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response({'error': 'The user who is requesting the changes does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if not user_asking_changes.id == id and not user_asking_changes.is_superuser:
        return Response({'error': 'You do not have permissions to update this user'}, status=status.HTTP_403_FORBIDDEN)

    try:
        user = User.objects.get(id=id)
    except User.DoesNotExist:
        return Response({'error': f'The user with the id {id} does not exist'}, status=status.HTTP_404_NOT_FOUND)

    serializer = UserSerializer(user, data=request.data)

    if serializer.is_valid():
        serializer.save()
        return Response({'message': 'User updated successfully'}, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def block_user(request, id):
    """
    Block a user.

    This view allows an admin to block a user.

    Args:
        request: The incoming request object.
        id (int): The ID of the user to block.

    Returns:
        Response: A JSON response indicating the result of the block operation.
    """
    try:
        user = User.objects.get(id=id)
    except User.DoesNotExist:
        return Response({'error': f'User with ID {id} does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if not user.is_active:
        return Response({'error': 'User is already blocked'}, status=status.HTTP_400_BAD_REQUEST)

    user.is_active = False
    user.save()

    return Response({'message': 'User has been blocked'}, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def unlock_user(request, id):
    """
    Unlock a user.

    This view allows an admin to unlock a user.

    Args:
        request: The incoming request object.
        id (int): The ID of the user to unlock.

    Returns:
        Response: A JSON response indicating the result of the unlock operation.
    """
    try:
        user = User.objects.get(id=id)
    except User.DoesNotExist:
        return Response({'error': f'User with ID {id} does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if user.is_active:
        return Response({'error': 'User is already unlocked'}, status=status.HTTP_400_BAD_REQUEST)

    user.is_active = True
    user.save()

    return Response({'message': 'User has been unlocked'}, status=status.HTTP_200_OK)


@api_view(['DELETE'])
@permission_classes([IsAdminUser])
def delete_user(request, id):
    """
    Delete a user.

    This view allows an admin to delete a user.

    Args:
        request: The incoming request object.
        id (int): The ID of the user to delete.

    Returns:
        Response: A JSON response indicating the result of the delete operation.
    """
    try:
        user = User.objects.get(id=id)
        user.delete()
        
        return Response({'message': f'User with ID {id} has been deleted'}, status=status.HTTP_200_OK)
    
    except User.DoesNotExist:
        return Response({'error': f'User with ID {id} does not exist'}, status=status.HTTP_404_NOT_FOUND)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def make_admin(request, id):
    """
    Make a user an admin.

    This view allows an admin to make another user an admin.

    Args:
        request: The incoming request object.
        id (int): The ID of the user to make an admin.

    Returns:
        Response: A JSON response indicating the result of the make_admin operation.
    """
    try:
        user = User.objects.get(id=id)
    except User.DoesNotExist:
        return Response({'error': f'User with ID {id} does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if not user.is_active:
        return Response({'error': f'User with ID {id} is not active'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    if user.is_staff:
        user.is_superuser = True
        user.save()
        return Response({'message': f'User with ID {id} is now an admin'})

    return Response({'error': f'User with ID {id} is not part of the staff'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)


@api_view(['POST'])
@permission_classes([IsAdminUser])
def make_staff(request, id):
    """
    Make a user a staff member.

    This view allows an admin to make another user a staff member.

    Args:
        request: The incoming request object.
        id (int): The ID of the user to make a staff member.

    Returns:
        Response: A JSON response indicating the result of the make_staff operation.
    """
    try:
        user = User.objects.get(id=id)
    except User.DoesNotExist:
        return Response({'error': f'User with ID {id} does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if not user.is_active:
        return Response({'error': f'User with ID {id} is not active'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    user.is_staff = True
    user.save()

    return Response({'message': f'User with ID {id} is now a staff member'}, status=status.HTTP_200_OK)

####################################################