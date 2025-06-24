from django.contrib import admin
from .models import CustomUser, Patient
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group

admin.site.unregister(Group)


class CustomUserAdmin(UserAdmin):
    model = CustomUser

    list_display = ('username', 'email', 'display_password_hash','role', 'last_login')
    list_filter = ('role', 'is_active', 'is_staff')
    search_fields = ('username', 'email')
    ordering = ('username',)

    fieldsets = (
        (None, {'fields': ('username', 'email', 'password', 'role')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    def display_password_hash(self, obj):
        return obj.password  # Django stores password hashes here
    display_password_hash.short_description = 'Password Hash'

class PatientAdmin(admin.ModelAdmin):
    list_display = ('name', 'patient_id', 'email', 'phone_number', 'medical_condition', 'gender')
    search_fields = ('name', 'patient_id', 'email', 'medical_condition')
    list_filter = ('gender',)
    ordering = ('name',)

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Patient, PatientAdmin)
