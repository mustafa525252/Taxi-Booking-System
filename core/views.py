from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from .models import AdminAccount, AdminPasswordResetOTP
# Random
import random
from datetime import timedelta
#timezone
from django.utils import timezone
from django.core.mail import send_mail
# Create your views here.


def login_view(request):

    if request.user.is_authenticated:
        if request.user.is_staff:
            return redirect('dashboard')

        return redirect('user_dashboard')

    if request.method == 'POST':

        role = request.POST.get('role')
        identity = request.POST.get('identity', '').strip()
        password = request.POST.get('password', '')

        if not identity or not password:
            messages.error(request, "Please enter your login credentials.")

        else:

            if role == 'admin':

                # Admin login using username
                user = authenticate(
                    request,
                    username=identity,
                    password=password
                )

                if user is not None and user.is_staff and user.is_superuser:
                    login(request, user)

                    if request.POST.get('remember'):
                        request.session.set_expiry(1209600)
                    else:
                        request.session.set_expiry(0)

                    return redirect('dashboard')

                messages.error(request, "Invalid admin username or password.")

            elif role == 'user':

                # Normal user login using email
                normal_user = User.objects.filter(
                    email__iexact=identity,
                    is_staff=False,
                    is_active=True
                ).first()

                if normal_user:
                    user = authenticate(
                        request,
                        username=normal_user.username,
                        password=password
                    )

                    if user is not None:
                        login(request, user)

                        if request.POST.get('remember'):
                            request.session.set_expiry(1209600)
                        else:
                            request.session.set_expiry(0)

                        return redirect('user_dashboard')

                messages.error(request, "Invalid email or password.")

            else:
                messages.error(request, "Invalid account type.")

    return render(request, 'core/login.html')


def logout_view(request):
    logout(request)
    messages.success(request, "You have been logged out successfully.")
    return redirect('login')

@user_passes_test(
    lambda user: user.is_authenticated and user.is_staff and user.is_superuser,
    login_url='login'
)
def dashboard(request):
    context = {
        'admin_name': request.user.username,
        'admin_email': request.user.email,
    }
    return render(request, 'core/dashboard.html', context)




def admin_register(request):

    if request.method == 'POST':

        full_name = request.POST.get('full_name', '').strip()
        email = request.POST.get('email', '').strip().lower()
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if not all([full_name, email, username, password, confirm_password]):
            messages.error(request, "All fields are required.")

        elif password != confirm_password:
            messages.error(request, "Passwords do not match.")

        elif len(password) < 8:
            messages.error(request, "Password must contain at least 8 characters.")

        elif AdminAccount.objects.filter(email__iexact=email).exists():
            messages.error(request, "Email already registered.")

        elif AdminAccount.objects.filter(username__iexact=username).exists():
            messages.error(request, "Username already exists.")

        else:
            admin = AdminAccount(
                full_name=full_name,
                email=email,
                username=username
            )

            admin.set_password(password)
            admin.save()

            messages.success(
                request,
                "Admin account registered successfully."
            )

            return redirect('login')

    return render(request, 'core/admin_register.html')





def admin_forgot_password(request):

    if request.method == 'POST':

        email = request.POST.get('email', '').strip().lower()

        request.session.pop('admin_reset_email', None)

        if not email:
            messages.error(request, "Please enter your email address.")

        else:
            admin = AdminAccount.objects.filter(
                email__iexact=email
            ).first()

            if admin:

                # Generate a six-digit OTP
                otp = str(random.randint(100000, 999999))

                # Remove previous unused OTPs
                AdminPasswordResetOTP.objects.filter(
                    admin=admin,
                    is_used=False
                ).delete()

                # Set OTP expiry to five minutes
                expiry_time = timezone.now() + timedelta(minutes=5)

                # Save OTP in database
                otp_record = AdminPasswordResetOTP.objects.create(
                    admin=admin,
                    otp_code=otp,
                    expires_at=expiry_time
                )

                try:
                    result = send_mail(
                        subject='Taxi Booking System - Password Reset OTP',

                        message=(
                            f'Hello {admin.full_name},\n\n'
                            f'Your password reset OTP is: {otp}\n\n'
                            'This OTP is valid for 5 minutes.\n'
                            'Please do not share this OTP with anyone.\n\n'
                            'Regards,\nTaxi Booking System'
                        ),

                        from_email=None,
                        recipient_list=[admin.email],
                        fail_silently=False
                    )

                    if result == 1:

                        request.session['admin_reset_email'] = admin.email

                        messages.success(
                            request,
                            "OTP has been sent successfully to your registered email address."
                        )

                    else:
                        otp_record.delete()

                        messages.error(
                            request,
                            "Unable to send OTP. Please try again."
                        )

                except Exception as e:
                    otp_record.delete()

                    print("EMAIL ERROR:", str(e))

                    messages.error(
                        request,
                        "Email delivery failed. Please check your email configuration."
                    )

            else:
                # Email is not registered
                messages.error(
                    request,
                    "This email address is not registered. Please enter a registered admin email."
                )

    return render(request, 'core/admin_forgot_password.html')
