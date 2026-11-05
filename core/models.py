
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone

class AdminAccount(models.Model):
    full_name = models.CharField(max_length=150)
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

    def is_expired(self):
        return timezone.now() >= self.expires_at

    def __str__(self):
        return f"OTP for {self.admin.email}"

    class Meta:
        db_table = 'admin_password_reset_otp'
        ordering = ['-created_at']