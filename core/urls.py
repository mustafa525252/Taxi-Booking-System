
from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin-register/', views.admin_register, name='admin_register'),
    path('admin-forgot-password/',views.admin_forgot_password,name='admin_forgot_password'),
    path('admin-verify-otp/',views.admin_verify_otp,name='admin_verify_otp'),
    path('admin-reset-password/',views.admin_reset_password,name='admin_reset_password'),
    path('drivers/', views.drivers_page, name='drivers'),
    path('users/', views.users_page, name='users'),
    path('bookings/', views.bookings_page, name='bookings'),
    path('user-list/', views.user_list, name='user_list'),
    path('logout/', views.logout_view, name='logout'),

]
