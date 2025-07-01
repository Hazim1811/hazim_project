from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import Group
from django.contrib.auth.hashers import make_password
from django.utils.crypto import get_random_string

from .models import CustomUser, Patient


@admin.action(description="Reset selected users’ passwords to a random temporary value")
def reset_to_temp(modeladmin, request, queryset):
    for user in queryset:
        temp_pw = get_random_string(10)
        user.password = make_password(temp_pw)
        user.must_change_password = True
        user.save()
        messages.info(
            request,
            f"{user.username}: temporary password is '{temp_pw}'"
        )


class CustomUserAdmin(UserAdmin):
    model = CustomUser

    list_display = ('username', 'email', 'display_password_hash','role', 'last_login')
    actions = [reset_to_temp]
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


admin.site.unregister(Group)
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Patient, PatientAdmin)
