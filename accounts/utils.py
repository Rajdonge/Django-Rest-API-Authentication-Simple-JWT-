from django.core.mail import send_mail
import random 
from django.conf import settings
from . models import User
from django.utils import timezone

def send_email_notification(email, purpose='email_verification', last_login=None, last_logout=None):
    try:
        user_obj = User.objects.get(email=email)

        if purpose in ['email_verification', 'resend_email_verification']:
            otp = random.randint(100000, 999999)
            user_obj.otp = otp
            user_obj.otp_created_at = timezone.now()
            subject = 'Your OTP to verify your account'
            message = f'Your OTP to verify your account is {otp}'
        
        elif purpose == 'account_verified':
            subject = 'Successfully verified'
            message = f'Your account {email} has been verified successfully.'
        
        elif purpose == 'reset_password_otp':
            otp = random.randint(100000, 999999)
            user_obj.otp = otp
            user_obj.otp_created_at = timezone.now()
            subject = 'Your OTP to reset password'
            message = f'Your OTP to reset password is {otp}'

        elif purpose == 'password_reset':
            user_obj.clear_otp()
            user_obj.otp_created = None
            subject = 'Password reset successfully'
            message = f'{email} Your password has been reset successfully.'
        
        elif purpose == 'login_notification':
            subject = 'New login detected'
            message = f'''
            Security Alert: New login detected
     
            Time: {user_obj.last_login}
 
            If this wasn't you, please secure your account immediately.
            '''

        elif purpose == 'logout_notification':
            subject = 'Logout successful'
            message = f'''
                You have successfully logout.
                Time: {user_obj.last_logout}
            '''

        elif purpose == 'update_password_notification':
            subject = 'Password updated'
            message = f'''
                Your password has been reset successfully.
            '''

        
        email_from = settings.EMAIL_HOST_USER
        recipient_list = [email]
        send_mail(subject, message, email_from, recipient_list)

        user_obj.save() # save changes only when otp is updated

        return user_obj.otp if purpose in ['email_verification', 'resend_email_verification', 'reset_password_otp'] else None


    except User.DoesNotExist:
        return None