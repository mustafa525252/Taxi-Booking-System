
from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('admin-register/', views.admin_register, name='admin_register'),
    path('logout/', views.logout_view, name='logout'),

]
