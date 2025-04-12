from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
import uuid
from django.utils import timezone
from datetime import timedelta
from rest_framework_simplejwt.tokens import RefreshToken

class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        return self.create_user(email, password, **extra_fields)
    


class User(AbstractUser):
    username = None
    GENDER_CHOICES = [
        ('male', 'male'),
        ('female', 'female'),
        ('other', 'other')
    ]
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=50)
    middle_name = models.CharField(max_length=50, blank=True, null=True)
    last_name = models.CharField(max_length=50)
    date_of_birth = models.DateField(blank=True, null=True)
    gender = models.CharField(choices=GENDER_CHOICES)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    address = models.CharField(max_length=100)
    phone = models.CharField(max_length=15)
    otp = models.CharField(max_length=10, blank=True, null=True)
    otp_created_at = models.DateTimeField(null=True, blank=True)
    is_otp_verified = models.BooleanField(default=False)
    otp_verified_at = models.DateTimeField(null=True, blank=True)
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    last_login = models.DateTimeField(auto_now=True)
    last_logout = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
    
    @property
    def get_full_name(self):
        return f"{self.first_name} {self.middle_name} {self.last_name}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # check otp expiration when the user instance is initialized
        self._check_otp_expiration()

    def save(self, *args, **kwargs):
        # check otp expiration before saving the user instance
        self._check_otp_expiration()
        super().save(*args, **kwargs)

    def _check_otp_expiration(self):
        # Check if the OTP has expired and reset it if necessary
        if self.otp_created_at and timezone.now() > self.otp_created_at + timedelta(minutes=1):
            # Logic to check if the OTP has expired (e.g., based on a timestamp)
            # If expired, reset the OTP and update the verification status
            self.clear_otp()

    # Method to clear otp
    def clear_otp(self):
        self.otp = None
        self.otp_created_at = None
        self.is_otp_verified = False
        self.otp_verified_at = None

    
    def tokens(self):
        refresh=RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }


