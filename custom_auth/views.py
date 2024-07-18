import string
import secrets
from datetime import datetime
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.shortcuts import get_object_or_404

# auth
import jwt
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.decorators import  permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

# send email
from django.conf import settings
from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.template.loader import render_to_string

# own imports
from users.models import User
from .models import AddressIP, Session, PasswordResetToken, ValidEmailToken

############# functions to help APIs #############

def create_token(model) -> str:
    """
    Generates a unique random token for a given model.

    The token is a string composed of 6 groups of 6 random characters (lowercase letters, digits, and uppercase letters)
    separated by hyphens. The function ensures the generated token is not already in use by checking the model's database.

    Args:
        model: The Django model for which the token is being generated.

    Returns:
        str: A unique random token as a string.
    """
    characters: str = string.ascii_lowercase + string.digits + string.ascii_uppercase
    
    while True:
        
        tokens = ["".join(secrets.choice(characters) for _ in range(6)) for _ in range(6)]
        token = "-".join(tokens)
        
        if model.objects.filter(token=token).count() == 0:
            return token


def register_session(request, user) -> str:
    """
    Registers a new session for a user.

    Creates a new session for the given user and associates it with their IP address.

    Args:
        request: The HTTP request object.
        user: The user object for which the session is being registered.

    Returns:
        str: The ID of the newly created session.
    """
    address_ip = AddressIP.objects.get_or_create(address_ip=request.META['REMOTE_ADDR'])
    session = Session(user_id=user, address_id=address_ip[0])
    session.save()
    
    return session.id

##########################

############# APIs #############

#3 login user
@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    """
    Handles user login and returns an access token and refresh token.

    Args:
        request (Request): The incoming request object.

    Returns:
        Response: A response object containing the access token, refresh token, and a success message.
    """
    # Searching username or email to search database
    username = request.data.get('username')
    email = request.data.get('email')

    if not (username or email):
        return Response({'error': 'You have to enter the username or email'}, 
                        status=status.HTTP_400_BAD_REQUEST)

    try:
        if username:
            user = User.objects.get(username=username)
        else:
            user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    # Valid password
    if not user.check_password(request.data['password']):
        return Response({'error': 'Invalid password'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if the user already has an active session
    # (You didn't provide the implementation of register_session, so I assume it's correct)
    register_session(request, user)

    # Generate tokens
    access_token = AccessToken.for_user(user)
    refresh_token = RefreshToken.for_user(user)

    result = {
        'access_token': str(access_token),
        'refresh_token': str(refresh_token),
        'message': 'Permission granted'
    }

    return Response(result, status=status.HTTP_202_ACCEPTED)


#3
@api_view(['POST'])
def validate_token_refresh(request):
    """
    Validates a refresh token and returns a 200 OK response if it's valid.

    Args:
        request (Request): The incoming request object.

    Returns:
        Response: A response object indicating whether the refresh token is valid or not.
    """
    refresh_token = request.data.get('refresh_token')  # Renamed to follow PEP 8 conventions

    if not refresh_token:
        return Response({'error': 'You have to enter the refresh token'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        payload = jwt.decode(refresh_token, settings.SECRET_KEY, algorithms=["HS256"], options={"verify_exp": True})
        return Response({'valid': True}, status=status.HTTP_200_OK)
    except jwt.ExpiredSignatureError:
        return Response({'valid': False, 'error': 'Refresh token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        return Response({'valid': False, 'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)


#3 validate if the access token is still valid
@api_view(['GET'])
def validate_token_access(request):
    """
    Validates an access token and returns a 200 OK response if it's valid.

    Args:
        request (Request): The incoming request object.

    Returns:
        Response: A response object indicating whether the access token is valid or not.
    """
    access_token = request.headers.get('Authorization')

    if not access_token:
        return Response({'error': 'You have to enter the access token'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        payload = jwt.decode(access_token, settings.SECRET_KEY, algorithms=["HS256"], options={"verify_exp": True})
        return Response({'valid': True}, status=status.HTTP_200_OK)
    except jwt.ExpiredSignatureError:
        return Response({'valid': False, 'error': 'Access token has expired'}, status=status.HTTP_401_UNAUTHORIZED)
    except jwt.InvalidTokenError:
        return Response({'valid': False, 'error': 'Invalid access token'}, status=status.HTTP_401_UNAUTHORIZED)


# get user logins
@api_view(['GET'])
@permission_classes([IsAdminUser])
def get_sessions(request, user_id):
    """
    Retrieves a list of sessions for a given user.

    Args:
        request (Request): The incoming request object.
        user_id (int): The ID of the user to retrieve sessions for.

    Returns:
        Response: A response object containing a list of sessions or a 204 No Content response if no sessions are found.
    """
    user = get_object_or_404(User, id=user_id)
    sessions = Session.objects.filter(user_id=user_id)

    if sessions.exists():
        result = [
            {
                'session_id': session.id,
                'user_id': session.user_id.id,
                'username': session.user_id.username,
                'ip_address': session.address_id.address_ip,
                'egistration_date': session.consultation_date
            }
            for session in sessions.all()
        ]
        return Response(result, status=status.HTTP_200_OK)

    return Response(status=status.HTTP_204_NO_CONTENT)


# send emails
@api_view(['POST'])
@permission_classes([IsAdminUser])
def send_validation_email(request, user_id):
    """
    Sends a validation email to a user.

    Args:
        request (Request): The incoming request object.
        user_id (int): The ID of the user to send the validation email to.

    Returns:
        Response: A response object indicating whether the email was sent successfully or not.
    """
    user = get_object_or_404(User, id=user_id)

    if user.is_validated:
        return Response({'error': 'The user is already validated'}, status=status.HTTP_401_UNAUTHORIZED)

    token = create_token(model=ValidEmailToken)
    ValidEmailToken.objects.create(user_id=user.id, token=token)

    # Send an email to the user to confirm their email address
    context = {
        'user': user,
        'change_password_url': f'http://127.0.0.1:8000/validate_email/{token}/',
        'year': datetime.now().year
    }

    html_content = render_to_string('emails/valid_email.html', context)
    plain_message = strip_tags(html_content)

    try:
        send_mail(
            subject='Verify Your Email',
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_content
        )
        return Response({'message': 'The email has been sent to the user'}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'error': 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# validates the user account and changes its status from is_active to true
@api_view(['POST'])
@permission_classes([AllowAny])
def validate_email(request, token):
    """
    Validates a user's email address using a token.

    Args:
        request (Request): The incoming request object.
        token (str): The validation token sent to the user's email.

    Returns:
        Response: A response object indicating whether the email was validated successfully or not.
    """
    if not token:
        return Response({'error': 'Token is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        email_token = ValidEmailToken.objects.get(token=token)
    except ValidEmailToken.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_401_UNAUTHORIZED)

    if email_token.is_expired():
        email_token.delete()
        return Response({'error': 'Token has expired, try again.'}, status=status.HTTP_400_BAD_REQUEST)

    user = email_token.user
    user.is_validated = True
    user.save()
    email_token.delete()

    # Send a notification email to the user
    context = {
        'user': user,
        'year': datetime.now().year
    }

    html_content = render_to_string('emails/valid_password_notification.html', context)
    plain_message = strip_tags(html_content)

    try:
        send_mail(
            subject='Account Validated successfully!',
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_content
        )
    except Exception as e:
        # Log the error or handle it differently if needed
        print(f"Error sending email: {e}")
        return Response({'error': 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({'message': 'Email validated successfully'}, status=status.HTTP_200_OK)


# Send the email with the token to change the password
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request(request):
    """
    Sends a password reset email to a user.

    Args:
        request (Request): The incoming request object.

    Returns:
        Response: A response object indicating whether the password reset email was sent successfully or not.
    """
    email = request.data.get('email')
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)

    if not user.is_validated:
        return Response({'error': 'This user\'s email is not validated'}, status=status.HTTP_405_METHOD_NOT_ALLOWED)

    token = create_token(model=PasswordResetToken)
    PasswordResetToken.objects.create(user_id=user.id, token=token)

    # Send email to the user with the token to change the password
    context = {
        'user': user,
        'change_password_url': f'http://example.com/change-password/{token}',
        'year': datetime.now().year
    }

    html_content = render_to_string('emails/change_password_email.html', context)
    plain_message = strip_tags(html_content)

    try:
        send_mail(
            subject='Change Password',
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_content
        )
    except Exception as e:
        # Log the error or handle it differently if needed
        print(f"Error sending email: {e}")
        return Response({'error': 'Failed to send password reset email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({'message': 'Password reset instructions have been sent to your email'}, status=status.HTTP_200_OK)


# allows you to change the password with the token that was sent by email
@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset(request, token):
    """
    Resets a user's password using a token sent by email.

    Args:
        request (Request): The incoming request object.
        token (str): The password reset token sent to the user's email.

    Returns:
        Response: A response object indicating whether the password was reset successfully or not.
    """
    password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')

    if not confirm_password or not password:
        return Response({'error': 'New password and confirm password are required'}, status=status.HTTP_400_BAD_REQUEST)

    if password != confirm_password:
        return Response({'error': 'New password and confirm password do not match'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        reset_token = PasswordResetToken.objects.get(token=token)
    except PasswordResetToken.DoesNotExist:
        return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)

    if reset_token.is_expired():
        reset_token.delete()
        return Response({'error': 'Token has expired'}, status=status.HTTP_400_BAD_REQUEST)

    user = reset_token.user
    user.set_password(password)
    user.save()
    reset_token.delete()

    # Send an email to notify the user that the password has been changed
    context = {
        'user': user,
        'year': datetime.now().year
    }

    html_content = render_to_string('emails/password_changed_notification.html', context)
    plain_message = strip_tags(html_content)

    try:
        send_mail(
            subject='Password Changed successfully!',
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            html_message=html_content
        )
    except Exception as e:
        # Log the error or handle it differently if needed
        print(f"Error sending email: {e}")
        return Response({'error': 'Failed to send password reset email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return Response({'message': 'Password reset successfully'}, status=status.HTTP_200_OK)

##########################

