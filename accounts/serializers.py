from datetime import timezone
from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

# User Registration Serializer
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'first_name', 'middle_name', 'last_name', 'date_of_birth', 'gender', 'address', 'phone', 'password', 'password2']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def validate(self, attrs):
        # validate password
        password = attrs.get('password')
        password2 = attrs.pop('password2')

        if password != password2:
            raise serializers.ValidationError({"error": "Passwords do not match"})
        return attrs
    

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    

# User Login Serializer
class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(style={'input_type':'password'}, write_only=True)
    access_token = serializers.CharField(read_only=True)
    refresh_token = serializers.CharField(read_only=True)
    class Meta:
        model = User
        fields = ['email', 'password', 'access_token', 'refresh_token']

    def validate(self, attrs):
        email = attrs.get('email').strip().lower()
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise serializers.ValidationError({"error":"Invalid credentials"})
        user_tokens = user.tokens()
        
        return {
            'email': user.email,
            'access_token': str(user_tokens.get('access')),
            'refresh_token': str(user_tokens.get('refresh'))
        }
    

# Send OTP Serializer
class SendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        email = value.lower().strip()
        if not User.objects.filter(email=email).exists():
            raise serializers.ValidationError({"error":"User with this email does not exist."})
        return value
    
# Verify OTP Serializer
class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    otp = serializers.CharField(required=True)

    def validate(self, data):
        email = data.get('email').lower().strip()
        otp = data.get('otp')

        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"error":"User with this email does not exist."})
        
        if user.otp != otp:
            raise serializers.ValidationError({"error":"Invalid OTP"})
        
        
        # Mark as verified (e.g. temporary flag in session or DB)
        user.is_otp_verified = True
        user.otp_verified_at = timezone.now()
        user.save()
        return data
    
# Reset Password Serializer
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    

    def validate(self, attrs):
        email = attrs.get('email').lower().strip()
        password = attrs.get('password')
        password2 = attrs.pop('password2')

        if password != password2:
            raise serializers.ValidationError({"error": "Passwords do not match"})
        
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"error":"User with this email does not exist."})
        
        # Verify OTP was verified
        if not user.is_otp_verified:
            raise serializers.ValidationError({"error":"OTP not verified. Please verify OTP first."})
        
        # Check if otp verified is still valid
        if user.otp_verified_at and timezone.now() > user.otp_verified_at + timezone.timedelta(minutes=1):
            raise serializers.ValidationError({"error":"OTP expired. Please request a new OTP."})
        new_password = attrs.get('password')
        user.set_password(new_password)
        user.otp = None
        user.is_otp_verified = False
        user.otp_verified_at = None
        user.save()
        return attrs
        
# User Logout Serializer
class UserLogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(required=True)

    default_error_messages = {
        'bad_token': ('Token is invalid or has expired')
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')
        return attrs
        
    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            raise self.fail('bad_token')
        

    

   