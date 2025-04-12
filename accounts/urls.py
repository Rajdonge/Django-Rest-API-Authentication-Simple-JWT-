from django.urls import path
from .views import UserRegistrationView, UserLoginView, ResendOTPView, PasswordResetRequestView, VerifyOtpView, ResetPasswordView, UserLogoutView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('login/', UserLoginView.as_view(), name='login'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend_otp'),
    path('password-reset-request/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('verify-otp/', VerifyOtpView.as_view(), name='verify_otp'), 
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('logout/', UserLogoutView.as_view(), name='logout'),
]