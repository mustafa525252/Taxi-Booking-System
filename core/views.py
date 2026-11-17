from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
from .models import AdminAccount, AdminPasswordResetOTP
import random
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.contrib.auth import get_user_model
from django.db import transaction
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

                # Admin login using custom AdminAccount
                admin = AdminAccount.objects.filter(
                    username__iexact=identity
                ).first()

                if admin and admin.check_password(password):

                    # Find matching Django User
                    django_user = User.objects.filter(
                        username__iexact=admin.username,
                        is_staff=True,
                        is_superuser=True,
                        is_active=True
                    ).first()

                    if django_user:
                        login(request, django_user)

                        if request.POST.get('remember'):
                            request.session.set_expiry(1209600)
                        else:
                            request.session.set_expiry(0)

                        return redirect('dashboard')

                messages.error(
                    request,
                    "Invalid admin username or password."
                )

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
    from .models import AdminAccount

    admin_account = AdminAccount.objects.filter(
        username=request.user.username
    ).first()

    context = {
        'admin_name': (
            admin_account.full_name
            if admin_account and admin_account.full_name
            else request.user.username
        ),
        'admin_email': request.user.email,
        'admin_profile': (
            admin_account.profile_image
            if admin_account and admin_account.profile_image
            else None
        ),
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

        elif User.objects.filter(username__iexact=username).exists():
            messages.error(request, "Username already exists in the system.")

        else:
            try:
                with transaction.atomic():

                    admin = AdminAccount(
                        full_name=full_name,
                        email=email,
                        username=username
                    )

                    admin.set_password(password)
                    admin.save()

                    User.objects.create_user(
                        username=username,
                        email=email,
                        password=password,
                        is_staff=True,
                        is_superuser=True
                    )

                messages.success(
                    request,
                    "Admin account registered successfully."
                )

                return redirect('login')

            except Exception as e:
                print("ADMIN REGISTRATION ERROR:", str(e))
                messages.error(
                    request,
                    "Unable to register admin account. Please try again."
                )

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

                        return redirect('admin_verify_otp')

                    else:
                        otp_record.delete()

                        messages.error(
                            request,
                            "Unable to generate OTP. Please try again."
                        )

                except Exception as e:
                    otp_record.delete()

                    print("EMAIL ERROR:", str(e))

                    messages.error(
                        request,
                        "OTP generation failed. Please try again."
                    )

            else:
                messages.error(
                    request,
                    "This email address is not registered. Please enter a registered admin email."
                )

    return render(request, 'core/admin_forgot_password.html')




def admin_verify_otp(request):

    email = request.session.get('admin_reset_email')

    if not email:
        messages.error(request, "Please request a new OTP first.")
        return redirect('admin_forgot_password')

    admin = AdminAccount.objects.filter(
        email__iexact=email
    ).first()

    if not admin:
        request.session.pop('admin_reset_email', None)
        messages.error(request, "Admin account not found.")
        return redirect('admin_forgot_password')

    otp_record = AdminPasswordResetOTP.objects.filter(
        admin=admin,
        is_used=False
    ).order_by('-created_at').first()

    if not otp_record:
        messages.error(request, "No active OTP found. Please request a new OTP.")
        return redirect('admin_forgot_password')

    if otp_record.is_expired():
        otp_record.delete()
        request.session.pop('admin_reset_email', None)
        messages.error(request, "OTP expired. Please request a new OTP.")
        return redirect('admin_forgot_password')

    if request.method == 'POST':

        entered_otp = request.POST.get('otp', '').strip()

        if not entered_otp:
            messages.error(request, "Please enter your OTP.")

        elif otp_record.attempts >= 5:
            otp_record.delete()
            request.session.pop('admin_reset_email', None)

            messages.error(
                request,
                "Maximum OTP attempts exceeded. Please request a new OTP."
            )

            return redirect('admin_forgot_password')

        elif entered_otp != otp_record.otp_code:

            otp_record.attempts += 1
            otp_record.save(update_fields=['attempts'])

            messages.error(
                request,
                f"Invalid OTP. {5 - otp_record.attempts} attempts remaining."
            )

        else:

            request.session['admin_otp_verified'] = True
            request.session['admin_verified_otp_id'] = otp_record.id

            messages.success(
                request,
                "OTP verified successfully."
            )

            return redirect('admin_reset_password')

    return render(request, 'core/admin_verify_otp.html')



User = get_user_model()

def admin_reset_password(request):
    email = request.session.get('admin_reset_email')
    otp_verified = request.session.get('admin_otp_verified')
    otp_id = request.session.get('admin_verified_otp_id')

    # Ensure the admin has verified the OTP
    if not email or not otp_verified or not otp_id:
        messages.error(request, "Please verify your OTP first.")
        return redirect('admin_forgot_password')

    admin = AdminAccount.objects.filter(email__iexact=email).first()

    if not admin:
        messages.error(request, "Admin account not found.")
        return redirect('admin_forgot_password')

    otp_record = AdminPasswordResetOTP.objects.filter(
        id=otp_id,
        admin=admin,
        is_used=False
    ).first()

    if not otp_record or otp_record.is_expired():
        request.session.pop('admin_reset_email', None)
        request.session.pop('admin_otp_verified', None)
        request.session.pop('admin_verified_otp_id', None)

        messages.error(request, "OTP is invalid or expired. Please request a new OTP.")
        return redirect('admin_forgot_password')

    if request.method == 'POST':
        new_password = request.POST.get('new_password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if not new_password or not confirm_password:
            messages.error(request, "Please fill in both password fields.")

        elif len(new_password) < 8:
            messages.error(request, "Password must contain at least 8 characters.")

        elif new_password != confirm_password:
            messages.error(request, "Passwords do not match.")

        else:
            try:
                with transaction.atomic():
                    # Recheck OTP inside the transaction
                    otp_record = AdminPasswordResetOTP.objects.select_for_update().filter(
                        id=otp_id,
                        admin=admin,
                        is_used=False
                    ).first()

                    if not otp_record or otp_record.is_expired():
                        messages.error(request, "OTP is invalid or expired. Please request a new OTP.")
                        return redirect('admin_forgot_password')

                    # Find the matching Django admin user
                    django_user = User.objects.filter(
                        username__iexact=admin.username,
                        is_staff=True,
                        is_superuser=True,
                        is_active=True
                    ).first()

                    if not django_user:
                        messages.error(request, "Matching Django admin account was not found.")
                        return redirect('admin_forgot_password')

                    # Update both passwords
                    admin.set_password(new_password)
                    admin.save(update_fields=['password'])

                    django_user.set_password(new_password)
                    django_user.save(update_fields=['password'])

                    # Prevent OTP reuse
                    otp_record.is_used = True
                    otp_record.save(update_fields=['is_used'])

                # Clear password-reset session data
                request.session.pop('admin_reset_email', None)
                request.session.pop('admin_otp_verified', None)
                request.session.pop('admin_verified_otp_id', None)

                messages.success(request, "Password reset successfully. Please log in with your new password.")
                return redirect('login')

            except Exception as e:
                print("PASSWORD RESET ERROR:", str(e))
                messages.error(request, "Unable to reset password. Please try again.")

    return render(request, 'core/admin_reset_password.html')



@user_passes_test(
    lambda user: user.is_authenticated and user.is_staff and user.is_superuser,
    login_url='login'
)
def drivers_page(request):
    return render(request, 'core/module_placeholder.html', {
        'module_title': 'Drivers',
        'module_icon': 'fa-id-card',
        'module_description': 'Driver management features will be available here soon.'
    })


@user_passes_test(
    lambda user: user.is_authenticated and user.is_staff and user.is_superuser,
    login_url='login'
)
def users_page(request):
    return render(request, 'core/module_placeholder.html', {
        'module_title': 'Users',
        'module_icon': 'fa-users',
        'module_description': 'User management features will be available here soon.'
    })


@user_passes_test(
    lambda user: user.is_authenticated and user.is_staff and user.is_superuser,
    login_url='login'
)
def bookings_page(request):
    return render(request, 'core/module_placeholder.html', {
        'module_title': 'Bookings',
        'module_icon': 'fa-calendar-check',
        'module_description': 'Booking management features will be available here soon.'
    })
