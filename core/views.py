from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import user_passes_test
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