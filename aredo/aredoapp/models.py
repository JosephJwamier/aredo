from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.conf import settings




class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(email, password, **extra_fields)

class Users(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.email



class Country(models.Model):
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=3, unique=True)  # e.g. "US", "KE", "UK"

    def __str__(self):
        return self.name




class University(models.Model):
    UNIVERSITY_TYPES = [
        ('public', 'Public'),
        ('private', 'Private'),
        ('international', 'International'),
        ('community', 'Community'),
    ]

    name = models.CharField(max_length=255)
    pdf = models.CharField(max_length=500)
    university_type = models.CharField(max_length=20, choices=UNIVERSITY_TYPES)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, related_name='universities')

    def __str__(self):
        return f"{self.name} - {self.country.name}"


class Applicant(models.Model):
    DEGREE_CHOICES = [
        ('bachelor', 'Bachelor'),
        ('master', 'Master'),
        ('phd', 'PhD'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='applications')
    university = models.ForeignKey('University', on_delete=models.CASCADE, related_name='applicants')
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models .CharField(max_length=20)
    degreenum = models .CharField(max_length=20)
    passport = models .CharField(max_length=20)
    degree = models.CharField(max_length=20, choices=DEGREE_CHOICES)
    department = models.CharField(max_length=100)
    deepdepartment = models.CharField(max_length=100)
    grad_univerBach = models.CharField(max_length=100)
    grad_univermaster = models.CharField(max_length=100)
    traker = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='applicant/')
    date_applied = models.DateTimeField(auto_now_add=True)


    touch = models.BooleanField(default=False)
    fees = models.CharField(max_length=100)
    submitted = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)
    accepted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.full_name} → {self.university.name}"

class CancelCode (models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='cancelcode')
    university = models.ForeignKey('University', on_delete=models.CASCADE, related_name='cancelcode')
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=255)
    traker = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='cancelcode/')


    touch = models.BooleanField(default=False)
    fees = models.CharField(max_length=100)
    submitted = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)


    def __str__(self):
        return f"{self.full_name} → {self.university.name}"



class News (models.Model):
    head = models.CharField(max_length=255)
    content = models.CharField(max_length=3000)
    pic = models.FileField(upload_to='news/')

    def __str__(self):
        return self.head

class Translate(models.Model):
    GOVERNORATE_CHOICES = [
        ('baghdad', 'Baghdad'),
        ('anbar', 'Anbar'),
        ('basra', 'Basra'),
        ('dhi_qar', 'Dhi Qar'),
        ('maysan', 'Maysan'),
        ('muthanna', 'Muthanna'),
        ('najaf', 'Najaf'),
        ('karbala', 'Karbala'),
        ('babil', 'Babil'),
        ('wasit', 'Wasit'),
        ('diwaniya', 'Diwaniya'),
        ('diyala', 'Diyala'),
        ('kirkuk', 'Kirkuk'),
        ('ninawa', 'Ninawa'),
        ('salah_al_din', 'Salah al-Din'),
        ('duhok', 'Duhok'),
        ('erbil', 'Erbil'),
        ('sulaymaniyah', 'Sulaymaniyah'),
        ('halabja', 'Halabja'),
    ]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='translate')
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    nearestPoint = models.CharField(max_length=255)
    govern = models.CharField(max_length=20, choices=GOVERNORATE_CHOICES)


    touch = models.BooleanField(default=False)
    fees = models.CharField(max_length=100)
    received = models.BooleanField(default=False)
    submitted = models.BooleanField(default=False)


class LangCourse(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='langcourse')
    university = models.ForeignKey('University', on_delete=models.CASCADE, related_name='langcourse')
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=255)
    passport = models.CharField(max_length=255)
    traker = models.CharField(max_length=255)
    pdf = models.FileField(upload_to='lang/')

    touch = models.BooleanField(default=False)
    fees = models.CharField(max_length=100)
    submitted = models.BooleanField(default=False)
    accepted = models.BooleanField(default=False)

class Universityfees(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='fees')
    university = models.ForeignKey('University', on_delete=models.CASCADE, related_name='fees')
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=255)
    department = models.CharField(max_length=255)
    univerFees = models.CharField(max_length=255)
    kind = models.CharField(max_length=255)



    touch = models.BooleanField(default=False)
    payoff = models.BooleanField(default=False)
    fees = models.CharField(max_length=100)
    submitted = models.BooleanField(default=False)


class Publish (models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='publish')
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=255)
    department = models.CharField(max_length=255)
    pages = models.CharField(max_length=255)
    magazine = models.CharField(max_length=255)
    mushref = models.CharField(max_length=255)
    publishResearch = models.BooleanField(default=False)
    time = models.DateTimeField(auto_now_add=True)
    stilal = models.BooleanField(default=False)
    international = models.BooleanField(default=False)


    touch = models.BooleanField(default=False)
    fees = models.CharField(max_length=100)
    payoff = models.BooleanField(default=False)
    submitted = models.BooleanField(default=False)