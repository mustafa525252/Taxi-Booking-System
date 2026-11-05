
from django.db import models
from django.contrib.auth.hashers import make_password, check_password


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
