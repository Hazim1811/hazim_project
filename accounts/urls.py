from django.urls import path
from . import views


urlpatterns = [
    path('', views.home_redirect, name='home_redirect'),
    path('register/', views.register, name='register'),
    path('register_success/', views.register_success, name='register_success'),
    path('login/', views.login_view, name='login'),
    path('qr_code/', views.qr_code, name='qr_code'),
    path('validate_qr/', views.validate_qr, name='validate_qr'),
    path('qr_status/', views.qr_status, name='qr_status'),
    path('doctor/', views.doctor_dashboard, name='doctor_dashboard'),
    path('update_patient/<str:patient_id>/', views.update_patient, name='update_patient'),
    path('update_success/', views.update_success, name='update_success'),
    path('delete_patient/<str:patient_id>/', views.delete_patient, name='delete_patient'),    
    path('nurse/', views.nurse_dashboard, name='nurse_dashboard'),
    path('change_password/', views.password_change, name='password_change'),
    path('change_success/', views.password_change_success, name='password_change_success'),
    path('mobile_login/', views.mobile_login, name='mobile_login'),
    path('private_key/<str:username>/', views.download_private_key, name='download_private_key'),
    path('logout/', views.logout_view, name='logout'),
    path('add_patient/', views.add_patient, name='add_patient'),
]