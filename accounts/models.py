from django.contrib.auth.models import AbstractUser
from django.db import models

class CustomUser(AbstractUser):
    ROLE_CHOICES = (
        ('admin', 'Admin'),
        ('doctor', 'Doctor'),
        ('nurse', 'Nurse'),
    )
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    public_key = models.TextField(blank=True, null=True)
    must_change_password = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username}({self.role})"
    
class Patient(models.Model):
    name = models.CharField(max_length=100)
    patient_id = models.CharField(max_length=20)
    email = models.EmailField()
    phone_number = models.CharField(max_length=15)
    medical_condition = models.CharField(max_length=255)
    gender = models.CharField(max_length=10)

    def __str__(self):
        return self.name
    