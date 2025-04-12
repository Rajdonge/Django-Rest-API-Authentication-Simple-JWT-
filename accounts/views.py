from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import UserRegistrationSerializer, UserLoginSerializer, SendOTPSerializer, VerifyOTPSerializer, ResetPasswordSerializer, UserLogoutSerializer
from .utils import *
from rest_framework.permissions import IsAuthenticated


# User Registration View
class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            email = request.data['email']

            # Send email verification notification
            send_email_notification(email=email, purpose='email_verification')

            return Response({"message": f"Your account registered successfully.  Please visit your email {email} to verify your account."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

# User Login View
class UserLoginView(APIView):
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        output = {
            'message': 'Login successful',
            'data': serializer.data
        }
        return Response(output,  status=status.HTTP_200_OK)
    

# Resend OTP View
class ResendOTPView(APIView):
    def post(self, request):
        data = request.data
        serializer = SendOTPSerializer(data=data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            send_email_notification(email=email, purpose='resend_email_verification')
            return Response({"message": f"OTP has been sent to your email {email}."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_404_NOT_FOUND)
    
# Reset Password Request View
class PasswordResetRequestView(APIView):
    def post(self, request):
        data = request.data
        serializer = SendOTPSerializer(data=data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            send_email_notification(email=email, purpose='reset_password_otp')
            return Response({"message": f"Password reset OTP has been sent to your email {email}."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Verify OTP View
class VerifyOtpView(APIView):
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message": "OTP verified successfully."}, status=status.HTTP_200_OK)

# Reset Password View
class ResetPasswordView(APIView):
    def post(self, request):
        data = request.data
        serializer = ResetPasswordSerializer(data=data)
        
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data['email']
            send_email_notification(email=email, purpose='password_reset')
            return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)     
    

# User Logout View
class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        serializer = UserLogoutSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Logout successful"}, status=status.HTTP_204_NO_CONTENT)

    

