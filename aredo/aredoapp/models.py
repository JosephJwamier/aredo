from django.conf import settings
import time
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
import uuid
from django.core.exceptions import ValidationError
import os
from PIL import Image
from django.utils.text import slugify
from datetime import datetime


class CustomUserManager(BaseUserManager):
    def create_user(self, phone_number, password=None, **extra_fields):
        if not phone_number:
            raise ValueError('Phone number is required')
        user = self.model(phone_number=phone_number, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, phone_number, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self.create_user(phone_number, password, **extra_fields)

class Users(AbstractBaseUser, PermissionsMixin):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    phone_number = models.CharField(max_length=15, unique=True)
    name = models.CharField(max_length=100)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = CustomUserManager()

    USERNAME_FIELD = 'phone_number'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.phone_number

class Country(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
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
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    country = models.ForeignKey(Country, on_delete=models.CASCADE, related_name='universities')

    def university_pdf_upload_to(instance, filename):
        """Construct upload path for university PDFs"""
        # Clean filename and ensure it's safe
        clean_filename = filename.replace(' ', '_')
        # Create path: uploads/universities/{country_code}/{university_name}/filename
        country_code = instance.country.code.lower() if instance.country else 'unknown'
        university_name = instance.name.replace(' ', '_').replace('/', '_')[:50]  # Limit length
        return f'uploads/universities/{country_code}/{university_name}/{clean_filename}'

    pdf = models.FileField(
        upload_to=university_pdf_upload_to,
        blank=True,
        null=True,
        help_text="PDF document for this university (brochure, info, etc.)"
    )
    university_type = models.CharField(max_length=20, choices=UNIVERSITY_TYPES)

    def __str__(self):
        return f"{self.name} - {self.country.name}"




class FormKind(models.Model):
    """Model to define different types of application forms"""



    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(
        max_length=30,
        unique=True,
        help_text="Unique identifier for the form type"
    )
    manager = models.CharField(
        max_length=100,
        help_text="Display name for the form type"
    )
    phonefield = models.TextField(
        blank=True,
        help_text="Detailed description of what this form type is for"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this form type is currently available for use"
    )
    requires_university = models.BooleanField(
        default=False,
        help_text="Whether this form type requires university selection"
    )
    requires_file_upload = models.BooleanField(
        default=False,
        help_text="Whether this form type requires file upload"
    )
    icon = models.CharField(
        max_length=50,
        blank=True,
        help_text="Icon class or name for UI display"
    )

    # spceify if the form need the field or not

    university =models.BooleanField(default=False)

    # Common required fields
    full_name = models.BooleanField(default=False)
    email = models.BooleanField(default=False)
    phone = models.BooleanField(default=False)
    notes = models.BooleanField(default=False)

    # Common optional fields
    department = models.BooleanField(default=False)
    fees = models.BooleanField(default=False)

    # Applicant-specific fields
    degreenum = models.BooleanField(default=False)
    passport = models.BooleanField(default=False)
    degree = models.BooleanField(default=False)
    deepdepartment = models.BooleanField(default=False)
    grad_univerBach = models.BooleanField(default=False)
    grad_univermaster =models.BooleanField(default=False)
    traker = models.BooleanField(default=False)


    pdf = models.BooleanField(default=False)

    # Translate-specific fields
    address = models.BooleanField(default=False)
    nearestPoint = models.BooleanField(default=False)
    govern = models.BooleanField(default=False)

    # flight
    by = models.BooleanField(default=False)

    # Publish-specific fields
    pages = models.BooleanField(default=False)
    magazine = models.BooleanField(default=False)
    mushref = models.BooleanField(default=False)
    publishResearch = models.BooleanField(default=False)
    stilal = models.BooleanField(default=False)
    international = models.BooleanField(default=False)

    # UniversityFees-specific fields
    univerFees = models.BooleanField(default=False)
    kind_fees = models.BooleanField(default=False)

    # Status flags
    touch = models.BooleanField(default=False)
    submitted = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)
    accepted = models.BooleanField(default=False)
    received = models.BooleanField(default=False)
    payoff = models.BooleanField(default=False)

    # Timestamps
    date_applied = models.BooleanField(default=False)
    date = models.BooleanField(default=False)


    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = [ 'name']
        verbose_name = 'Form Kind'
        verbose_name_plural = 'Form Kinds'

    def __str__(self):
        return self.name

    def get_field_requirements_dict(self):
        """Return a dictionary of field requirements"""
        return {
            'university': self.university,
            'full_name': self.full_name,
            'email': self.email,
            'phone': self.phone,
            'notes': self.notes,
            'department': self.department,
            'fees': self.fees,
            'degreenum': self.degreenum,
            'passport': self.passport,
            'degree': self.degree,
            'deepdepartment': self.deepdepartment,
            'grad_univerBach': self.grad_univerBach,
            'grad_univermaster': self.grad_univermaster,
            'traker': self.traker,
            'pdf': self.pdf,
            'address': self.address,
            'nearestPoint': self.nearestPoint,
            'govern': self.govern,
            'by': self.by,
            'pages': self.pages,
            'magazine': self.magazine,
            'mushref': self.mushref,
            'publishResearch': self.publishResearch,
            'stilal': self.stilal,
            'international': self.international,
            'univerFees': self.univerFees,
            'kind_fees': self.kind_fees,
            'touch': self.touch,
            'submitted': self.submitted,
            'approved': self.approved,
            'accepted': self.accepted,
            'received': self.received,
            'payoff': self.payoff,
            'date_applied': self.date_applied,
            'date': self.date,
        }

    def get_required_fields_list(self):
        """Get list of required field names"""
        requirements = self.get_field_requirements_dict()
        return [field_name for field_name, is_required in requirements.items() if is_required]

    def get_optional_fields_list(self):
        """Get list of optional field names"""
        requirements = self.get_field_requirements_dict()
        return [field_name for field_name, is_required in requirements.items() if not is_required]


    @classmethod
    def get_active_kinds(cls):
        """Return queryset of active form kinds"""
        return cls.objects.filter(is_active=True)


class ApplicationForm(models.Model):
    """Unified model for all types of application forms"""

    DEGREE_CHOICES = [
        ('bachelor', 'Bachelor'),
        ('master', 'Master'),
        ('phd', 'PhD'),
    ]
    By = [
        ('flight ', 'Flight'),
        ('taxi', 'Taxi'),
        ('train', 'Train'),
        ('autobus', 'Autobus'),
    ]

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
        ('duhuk', 'Duhok'),
        ('erbil', 'Erbil'),
        ('sulaymaniyah', 'Sulaymaniyah'),
        ('halabja', 'Halabja'),
    ]

    # Primary fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.ForeignKey(
        FormKind,
        on_delete=models.PROTECT,
        related_name='applications',
        help_text="Type of application form"
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='forms'
    )
    university = models.ForeignKey(
        'University',
        on_delete=models.CASCADE,
        related_name='forms',
        null=True,
        blank=True
    )

    # Common required fields
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=255)
    notes = models.CharField(max_length=500)

    # Common optional fields
    department = models.CharField(max_length=255, blank=True)
    fees = models.CharField(max_length=100, blank=True)

    # Applicant-specific fields
    degreenum = models.CharField(max_length=20, blank=True)
    passport = models.CharField(max_length=255, blank=True)
    degree = models.CharField(max_length=20, choices=DEGREE_CHOICES, blank=True)
    deepdepartment = models.CharField(max_length=100, blank=True)
    grad_univerBach = models.CharField(max_length=100, blank=True)
    grad_univermaster = models.CharField(max_length=100, blank=True)
    traker = models.CharField(max_length=255, blank=True)

    def upload_to(instance, filename):
        """Construct upload path based on form kind, user, and timestamp"""
        # Get user folder
        user_folder = str(instance.user.id)
        # Get kind folder
        kind_folder = instance.kind.name if instance.kind else 'other'
        # Split name and extension
        base, ext = os.path.splitext(filename)
        # Add timestamp
        timestamp = int(time.time())
        new_filename = f"{base}_{timestamp}{ext}"

        return f'uploads/{kind_folder}/{user_folder}/{new_filename}'
    pdf = models.FileField(upload_to=upload_to, blank=True, null=True)

    # Translate-specific fields
    address = models.CharField(max_length=255, blank=True)
    nearestPoint = models.CharField(max_length=255, blank=True)
    govern = models.CharField(max_length=20, choices=GOVERNORATE_CHOICES, blank=True)

    #flight
    by = models.CharField(max_length=20, choices=GOVERNORATE_CHOICES, blank=True)

    # Publish-specific fields
    pages = models.CharField(max_length=255, blank=True)
    magazine = models.CharField(max_length=255, blank=True)
    mushref = models.CharField(max_length=255, blank=True)
    publishResearch = models.BooleanField(default=False)
    stilal = models.BooleanField(default=False)
    international = models.BooleanField(default=False)

    # UniversityFees-specific fields
    univerFees = models.CharField(max_length=255, blank=True)
    kind_fees = models.CharField(max_length=255, blank=True)

    # Status flags
    touch = models.BooleanField(default=False)
    submitted = models.BooleanField(default=False)
    approved = models.BooleanField(default=False)
    accepted = models.BooleanField(default=False)
    received = models.BooleanField(default=False)
    payoff = models.BooleanField(default=False)

    # Timestamps
    date_applied = models.DateTimeField(auto_now_add=True)
    date = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save_images(self, image_files):
        """
        Save multiple images for this application form

        Args:
            image_files: List of uploaded image files

        Returns:
            List of created ApplicationImage instances
        """
        created_images = []

        for image_file in image_files:
            # Validate image
            if self.is_valid_image(image_file):
                # Create ApplicationImage instance
                app_image = ApplicationImage.objects.create(
                    form=self,
                    image=image_file
                )
                created_images.append(app_image)

        return created_images

    def is_valid_image(self, image_file):
        """Validate if uploaded file is a valid image"""
        try:
            # Check file extension
            valid_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']
            file_ext = os.path.splitext(image_file.name)[1].lower()

            if file_ext not in valid_extensions:
                return False

            # Check if file can be opened as image
            Image.open(image_file)
            return True

        except Exception:
            return False

    def get_images(self):
        """Get all images associated with this form"""
        return self.images.all()

    def get_image_urls(self):
        """Get URLs of all images"""
        return [img.image.url for img in self.images.all()]

    class Meta:
        ordering = ['-date_applied']
        verbose_name = 'Application Form'
        verbose_name_plural = 'Application Forms'
        indexes = [
            models.Index(fields=['kind', 'user']),
            models.Index(fields=['date_applied']),
            models.Index(fields=['submitted', 'approved']),
        ]

    def __str__(self):
        return f"{self.full_name} ({self.kind.name})"



    def _validate_by_kind(self):
        """Perform kind-specific validation"""
        if self.kind.name == FormKind.APPLICANT:
            if self.degree and self.degree == 'master' and not self.grad_univerBach:
                raise ValidationError({
                    'grad_univerBach': 'Bachelor graduation university is required for Master degree applications'
                })
            if self.degree and self.degree == 'phd' and not self.grad_univermaster:
                raise ValidationError({
                    'grad_univermaster': 'Master graduation university is required for PhD applications'
                })

        elif self.kind.name == FormKind.UNIVERSITY_FEES:
            if self.univerFees and not self.univerFees.isdigit():
                raise ValidationError({
                    'univerFees': 'University fees must be a valid number'
                })

    @property
    def status_display(self):
        """Return human-readable status"""
        if self.received:
            return "Received"
        elif self.accepted:
            return "Accepted"
        elif self.approved:
            return "Approved"
        elif self.submitted:
            return "Submitted"
        elif self.touch:
            return "In Progress"
        else:
            return "Draft"

    @property
    def is_editable(self):
        """Check if form can still be edited"""
        return not (self.submitted or self.approved or self.accepted or self.received)



    def clean(self):
        """Enhanced validation based on form kind requirements"""
        super().clean()

        if not self.kind:
            return

        # Use the validation function from serializers
        try:
            from .serializers import validate_application_form_data
            validate_application_form_data(self)
        except ImportError:
            # Fallback to basic validation if serializer is not available
            self._basic_form_validation()

    def _basic_form_validation(self):
        """Basic validation when serializer validation is not available"""
        if not self.kind.is_active:
            raise ValidationError("This form type is currently not available")

        # Get required fields from the form kind
        required_fields = self.get_required_fields_from_kind()

        # Check for missing required fields
        missing_fields = []
        for field_name in required_fields:
            mapped_field = self.map_kind_field_to_form_field(field_name)
            field_value = getattr(self, mapped_field, None)
            if not field_value and field_value != 0 and field_value is not False:
                missing_fields.append(mapped_field)

        if missing_fields:
            error_dict = {}
            for field in missing_fields:
                error_dict[field] = f"This field is required for {self.kind.manager} applications"
            raise ValidationError(error_dict)

    def get_required_fields_from_kind(self):
        """Get required field names from the associated FormKind"""
        if not self.kind:
            return []

        required_fields = []

        # Map of FormKind boolean fields to their names
        field_mappings = {
            'university': self.kind.university,
            'full_name': self.kind.full_name,
            'email': self.kind.email,
            'phone': self.kind.phone,
            'notes': self.kind.notes,
            'department': self.kind.department,
            'fees': self.kind.fees,
            'degreenum': self.kind.degreenum,
            'passport': self.kind.passport,
            'degree': self.kind.degree,
            'deepdepartment': self.kind.deepdepartment,
            'grad_univerBach': self.kind.grad_univerBach,
            'grad_univermaster': self.kind.grad_univermaster,
            'traker': self.kind.traker,
            'pdf': self.kind.pdf,
            'address': self.kind.address,
            'nearestPoint': self.kind.nearestPoint,
            'govern': self.kind.govern,
            'by': self.kind.by,
            'pages': self.kind.pages,
            'magazine': self.kind.magazine,
            'mushref': self.kind.mushref,
            'publishResearch': self.kind.publishResearch,
            'stilal': self.kind.stilal,
            'international': self.kind.international,
            'univerFees': self.kind.univerFees,
            'kind_fees': self.kind.kind_fees,
            'touch': self.kind.touch,
            'submitted': self.kind.submitted,
            'approved': self.kind.approved,
            'accepted': self.kind.accepted,
            'received': self.kind.received,
            'payoff': self.kind.payoff,
            'date_applied': self.kind.date_applied,
            'date': self.kind.date,
        }

        for field_name, is_required in field_mappings.items():
            if is_required:
                required_fields.append(field_name)

        return required_fields

    def map_kind_field_to_form_field(self, kind_field_name):
        """Map FormKind field names to ApplicationForm field names"""
        field_mapping = {
            'phone': 'phone',  # FormKind uses 'phonefield', ApplicationForm uses 'phone'
        }
        return field_mapping.get(kind_field_name, kind_field_name)

    def get_required_fields(self):
        """Get required fields for this form's kind - updated method"""
        required_fields = self.get_required_fields_from_kind()
        return [self.map_kind_field_to_form_field(field) for field in required_fields]

    def get_completion_percentage(self):
        """Calculate form completion percentage based on kind requirements"""
        if not self.kind:
            return 0

        required_fields = self.get_required_fields_from_kind()
        if not required_fields:
            return 100

        completed_fields = 0
        for field_name in required_fields:
            mapped_field = self.map_kind_field_to_form_field(field_name)
            field_value = getattr(self, mapped_field, None)

            # Consider field completed if it has a value (including False for boolean fields)
            if field_value or field_value is False:
                completed_fields += 1

        return int((completed_fields / len(required_fields)) * 100)

    def is_complete(self):
        """Check if all required fields are completed"""
        return self.get_completion_percentage() == 100

    def get_missing_required_fields(self):
        """Get list of missing required fields"""
        if not self.kind:
            return []

        required_fields = self.get_required_fields_from_kind()
        missing_fields = []

        for field_name in required_fields:
            mapped_field = self.map_kind_field_to_form_field(field_name)
            field_value = getattr(self, mapped_field, None)
            if not field_value and field_value != 0 and field_value is not False:
                missing_fields.append(mapped_field)

        return missing_fields

    @property
    def can_be_submitted(self):
        """Check if form can be submitted (all required fields completed)"""
        return self.is_complete() and self.is_editable

    def save(self, *args, **kwargs):
        """Override save to run validation"""
        self.full_clean()  # This will call clean() method
        super().save(*args, **kwargs)


def upload_to_images(instance, filename):
    ext = filename.split('.')[-1]
    unique_name = f"{uuid.uuid4()}.{ext}"
    return f'uploads/{instance.form.kind}/{instance.form.user.name}/images/{unique_name}'


class ApplicationImage(models.Model):
    IMAGE_TYPES = [
        ('passport', 'Passport'),
        ('certificate', 'Certificate'),
        ('transcript', 'Transcript'),
        ('id_document', 'ID Document'),
        ('supporting_doc', 'Supporting Document'),
        ('other', 'Other'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    form = models.ForeignKey(ApplicationForm, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to=upload_to_images)
    image_type = models.CharField(
        max_length=20,
        default='other',
        help_text="Type of document in the image"
    )
    description = models.CharField(max_length=255, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Image metadata
    file_size = models.PositiveIntegerField(null=True, blank=True)  # in bytes
    width = models.PositiveIntegerField(null=True, blank=True)
    height = models.PositiveIntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-uploaded_at']

    def save(self, *args, **kwargs):
        if self.image:
            # Get image dimensions and file size
            try:
                with Image.open(self.image) as img:
                    self.width, self.height = img.size
                self.file_size = self.image.size
            except Exception:
                pass

        super().save(*args, **kwargs)

    def __str__(self):
        return f"Image for {self.form.full_name} ({self.get_image_type_display()})"

    @property
    def file_size_mb(self):
        """Return file size in MB"""
        if self.file_size:
            return round(self.file_size / (1024 * 1024), 2)
        return 0


class NewsType(models.Model):
    """Model for categorizing news types"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    slug = models.SlugField(max_length=100, unique=True, blank=True)
    description = models.TextField(blank=True, null=True)
    color = models.CharField(max_length=7, default='#007bff', help_text='Hex color code for UI')
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        verbose_name = 'News Type'
        verbose_name_plural = 'News Types'

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name)
        super().save(*args, **kwargs)

    @classmethod
    def get_active_types(cls):
        """Get all active news types"""
        return cls.objects.filter(is_active=True)


class News(models.Model):
    """News model with proper ForeignKey relationship"""


    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    title = models.CharField(max_length=255, help_text='News headline')
    content = models.TextField(help_text='Main news content')
    # CHANGED: Use ForeignKey instead of UUIDField
    news_type = models.ForeignKey(
        NewsType,
        on_delete=models.CASCADE,
        related_name='news_articles',
        help_text='News category'
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'News Article'
        verbose_name_plural = 'News Articles'

    def __str__(self):
        return self.title


def custom_image_upload_path(instance, filename):
    """
    Custom upload path: news/newstitle/originalname_timestamp.extension
    """
    # Get file extension and original name
    original_name = os.path.splitext(filename)[0]
    ext = os.path.splitext(filename)[1][1:] if '.' in filename else 'jpg'

    # Clean news title for directory name
    news_title = slugify(instance.news.title)

    # Create timestamp with microseconds
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]  # microseconds to milliseconds

    # Create filename: originalname_timestamp.extension
    # Clean the original name to be filesystem safe
    safe_original_name = slugify(original_name)
    new_filename = f"{safe_original_name}_{timestamp}.{ext}"

    # Return full path: news/newstitle/originalname_timestamp.extension
    return os.path.join('news', news_title, new_filename)

class NewsImage(models.Model):

    news = models.ForeignKey('News', on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to=custom_image_upload_path)

    title = models.CharField(max_length=200, blank=True)
    caption = models.TextField(blank=True)
    order = models.PositiveIntegerField(default=0)
    is_active = models.BooleanField(default=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['order', 'uploaded_at']
        verbose_name = 'News Image'
        verbose_name_plural = 'News Images'

    def __str__(self):
        return f"{self.news.title}  - {self.uploaded_at}"

    @property
    def file_size_human(self):
        """Return human readable file size"""
        if not self.image:
            return "0 bytes"

        try:
            size = self.image.size
            for unit in ['bytes', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        except:
            return "Unknown size"

    def delete(self, *args, **kwargs):
        """Override delete to also remove the physical file"""
        if self.image:
            storage = self.image.storage
            if storage.exists(self.image.name):
                storage.delete(self.image.name)
        super().delete(*args, **kwargs)
