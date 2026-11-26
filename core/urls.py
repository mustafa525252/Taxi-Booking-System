
from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('user-dashboard/', views.user_dashboard, name='user_dashboard'),
    path('admin-register/', views.admin_register, name='admin_register'),
    path('admin-forgot-password/',views.admin_forgot_password,name='admin_forgot_password'),
    path('admin-verify-otp/',views.admin_verify_otp,name='admin_verify_otp'),
    path('admin-reset-password/',views.admin_reset_password,name='admin_reset_password'),
    path('drivers/', views.drivers_page, name='drivers'),
    path('drivers/<int:driver_id>/',views.driver_detail,name='driver_detail'),
    path('drivers/add/',views.add_driver,name='add_driver'),
    path('drivers/<int:driver_id>/delete/',views.delete_driver,name='delete_driver'),
    path('users/', views.users_page, name='users'),
    path('bookings/', views.bookings_page, name='bookings'),
    path('user-list/', views.user_list, name='user_list'),
    path('user-detail/<int:user_id>/',views.user_detail,name='user_detail'),
    path('add-customer/', views.add_customer, name='add_customer'),
    path('user-register/', views.user_register, name='user_register'),
    #user_forgot_password
    path('user-forgot-password/',views.user_forgot_password,name='user_forgot_password'),
    path('user-verify-otp/',views.user_verify_otp,name='user_verify_otp'),
    path('driver-register/',views.driver_register,name='driver_register'),
    path('logout/', views.logout_view, name='logout'),

]
