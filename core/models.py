
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
from django.conf import settings


class AdminAccount(models.Model):
    full_name = models.CharField(max_length=150)

    profile_image = models.ImageField(
        upload_to='admin_profiles/',
        blank=True,
        null=True
    )

    email = models.EmailField(unique=True)
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def __str__(self):
        return self.username

    class Meta:
        db_table = 'custom_admin'
        verbose_name = 'Admin Account'
        verbose_name_plural = 'Admin Accounts'


class AdminPasswordResetOTP(models.Model):

    admin = models.ForeignKey(
        AdminAccount,
        on_delete=models.CASCADE,
        related_name='password_reset_otps'
    )

    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def __str__(self):
        return f"OTP for {self.admin.email}"

    class Meta:
        db_table = 'admin_password_reset_otp'
        ordering = ['-created_at']
        
        
class CustomerProfile(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='customer_profile'
    )
    full_name = models.CharField(max_length=150)
    mobile = models.CharField(max_length=15, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.full_name

    class Meta:
        db_table = 'customer_profile'
        verbose_name = 'Customer Profile'
        verbose_name_plural = 'Customer Profiles'
        
        

class Driver(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='driver_profile'
    )

    license_number = models.CharField(
        max_length=50,
        unique=True
    )

    mobile = models.CharField(
        max_length=15,
        unique=True
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.get_full_name() or self.user.username

    class Meta:
        db_table = 'driver_profile'
        verbose_name = 'Driver'
        verbose_name_plural = 'Drivers'



class UserPasswordResetOTP(models.Model):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='password_reset_otps'
    )

    otp_code = models.CharField(max_length=6)

    created_at = models.DateTimeField(auto_now_add=True)

    expires_at = models.DateTimeField()

    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return f"Password Reset OTP - {self.user.email}"

    class Meta:
        db_table = 'user_password_reset_otp'
        verbose_name = 'User Password Reset OTP'
        verbose_name_plural = 'User Password Reset OTPs'



class DriverPasswordResetOTP(models.Model):

    driver = models.ForeignKey(
        Driver,
        on_delete=models.CASCADE,
        related_name='password_reset_otps'
    )

    otp_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def __str__(self):
        return f"Driver Password Reset OTP - {self.driver.user.email}"

    class Meta:
        db_table = 'driver_password_reset_otp'
        ordering = ['-created_at']
