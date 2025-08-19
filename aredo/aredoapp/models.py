from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
import uuid
from django.core.exceptions import ValidationError
import os
from PIL import Image

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
    country = models.ForeignKey(Country, on_delete=models.CASCADE, related_name='universities')

    def __str__(self):
        return f"{self.name} - {self.country.name}"




class FormKind(models.Model):
    """Model to define different types of application forms"""

    # Predefined form types
    APPLICANT = 'applicant'
    CANCEL_CODE = 'cancelcode'
    TRANSLATE = 'translate'
    LANGUAGE_COURSE = 'langcourse'
    UNIVERSITY_FEES = 'universityfees'
    PUBLISH_RESEARCH = 'publish'
    DELVARY = 'delvary'
    FLIGHT = 'flight'
    TRANSLATE_IRAQ = 'translate iraq'
    ISTALAL = 'istalal'
    RAHGERY = 'rahgery'
    HIGHER_EDUCATION = 'higher education'
    FORM_TYPE_CHOICES = [
        (APPLICANT, 'Applicant'),
        (CANCEL_CODE, 'Cancel Code'),
        (TRANSLATE, 'Translate'),
        (LANGUAGE_COURSE, 'Language Course'),
        (UNIVERSITY_FEES, 'University Fees'),
        (PUBLISH_RESEARCH, 'Publish Research'),
    ]


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
    phone = models.TextField(
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


    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = [ 'name']
        verbose_name = 'Form Kind'
        verbose_name_plural = 'Form Kinds'

    def __str__(self):
        return self.name

    def get_required_fields(self):
        """Return list of required fields for this form kind"""
        required_fields_map = {
            self.APPLICANT: [
                'university', 'passport', 'degree', 'degreenum',
                'traker', 'pdf', 'deepdepartment', 'grad_univerBach',
                'grad_univermaster'
            ],
            self.CANCEL_CODE: [
                'university', 'traker', 'pdf'
            ],
            self.TRANSLATE: [
                'address', 'nearestPoint', 'govern'
            ],
            self.LANGUAGE_COURSE: [
                'university', 'passport', 'traker', 'pdf'
            ],
            self.UNIVERSITY_FEES: [
                'university', 'department', 'univerFees', 'kind_fees'
            ],
            self.PUBLISH_RESEARCH: [
                'department', 'pages', 'magazine', 'mushref'
            ],
        }
        return required_fields_map.get(self.name, [])

    @classmethod
    def get_active_kinds(cls):
        """Return queryset of active form kinds"""
        return cls.objects.filter(is_active=True)


class FormKindField(models.Model):
    """Model to define which fields are required/optional for each form kind"""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    form_kind = models.ForeignKey(
        FormKind,
        on_delete=models.CASCADE,
        related_name='required_fields'
    )
    field_name = models.CharField(
        max_length=50,
        help_text="Name of the field in ApplicationForm model"
    )
    is_required = models.BooleanField(
        default=True,
        help_text="Whether this field is required for this form kind"
    )
    display_name = models.CharField(
        max_length=100,
        blank=True,
        help_text="Human-readable name for the field"
    )
    help_text = models.CharField(
        max_length=255,
        blank=True,
        help_text="Help text to display for this field"
    )
    field_order = models.PositiveIntegerField(
        default=0,
        help_text="Order in which to display this field in forms"
    )

    class Meta:
        unique_together = ['form_kind', 'field_name']
        ordering = ['field_order', 'field_name']
        verbose_name = 'Form Kind Field'
        verbose_name_plural = 'Form Kind Fields'

    def __str__(self):
        return f"{self.form_kind.name} - {self.field_name}"


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
        """Construct upload path based on form kind and user"""
        user_folder = instance.user.username if hasattr(instance.user, 'username') else str(instance.user.id)
        kind_folder = instance.kind.name if instance.kind else 'other'
        return f'uploads/{kind_folder}/{user_folder}/{filename}'

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

    def clean(self):
        """Validate form based on kind requirements"""
        super().clean()

        if not self.kind:
            return

        # Get required fields from the form kind
        required_fields = self.kind.get_required_fields()

        # Check for missing required fields
        missing_fields = []
        for field_name in required_fields:
            field_value = getattr(self, field_name, None)
            if not field_value:
                missing_fields.append(field_name)

        if missing_fields:
            error_dict = {}
            for field in missing_fields:
                error_dict[field] = f"This field is required for {self.kind.name} applications"
            raise ValidationError(error_dict)

        # Additional validation based on form kind
        self._validate_by_kind()

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

    def get_required_fields(self):
        """Get required fields for this form's kind"""
        if self.kind:
            return self.kind.get_required_fields()
        return []

    def get_completion_percentage(self):
        """Calculate form completion percentage"""
        if not self.kind:
            return 0

        required_fields = self.get_required_fields()
        if not required_fields:
            return 100

        completed_fields = 0
        for field_name in required_fields:
            field_value = getattr(self, field_name, None)
            if field_value:
                completed_fields += 1

        return int((completed_fields / len(required_fields)) * 100)



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
        choices=IMAGE_TYPES,
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

class News (models.Model):
    head = models.CharField(max_length=255)
    content = models.CharField(max_length=3000)
    pic = models.FileField(upload_to='news/')

    def __str__(self):
        return self.head

# class Applicant(models.Model):
#     DEGREE_CHOICES = [
#         ('bachelor', 'Bachelor'),
#         ('master', 'Master'),
#         ('phd', 'PhD'),
#     ]
#
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='applications')
#     university = models.ForeignKey('University', on_delete=models.CASCADE, related_name='applicants')
#     full_name = models.CharField(max_length=255)
#     email = models.EmailField()
#     phone = models .CharField(max_length=20)
#     degreenum = models .CharField(max_length=20)
#     passport = models .CharField(max_length=20)
#     degree = models.CharField(max_length=20, choices=DEGREE_CHOICES)
#     department = models.CharField(max_length=100)
#     deepdepartment = models.CharField(max_length=100)
#     grad_univerBach = models.CharField(max_length=100)
#     grad_univermaster = models.CharField(max_length=100)
#     traker = models.CharField(max_length=255)
#     pdf = models.FileField(upload_to='applicant/')
#     date_applied = models.DateTimeField(auto_now_add=True)
#
#
#     touch = models.BooleanField(default=False)
#     fees = models.CharField(max_length=100)
#     submitted = models.BooleanField(default=False)
#     approved = models.BooleanField(default=False)
#     accepted = models.BooleanField(default=False)
#
#     def __str__(self):
#         return f"{self.full_name} → {self.university.name}"
#
# class CancelCode (models.Model):
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='cancelcode')
#     university = models.ForeignKey('University', on_delete=models.CASCADE, related_name='cancelcode')
#     full_name = models.CharField(max_length=255)
#     email = models.EmailField()
#     phone = models.CharField(max_length=255)
#     traker = models.CharField(max_length=255)
#     pdf = models.FileField(upload_to='cancelcode/')
#
#
#     touch = models.BooleanField(default=False)
#     fees = models.CharField(max_length=100)
#     submitted = models.BooleanField(default=False)
#     approved = models.BooleanField(default=False)
#
#
#     def __str__(self):
#         return f"{self.full_name} → {self.university.name}"
#
#
#
#
# class Translate(models.Model):
#     GOVERNORATE_CHOICES = [
#         ('baghdad', 'Baghdad'),
#         ('anbar', 'Anbar'),
#         ('basra', 'Basra'),
#         ('dhi_qar', 'Dhi Qar'),
#         ('maysan', 'Maysan'),
#         ('muthanna', 'Muthanna'),
#         ('najaf', 'Najaf'),
#         ('karbala', 'Karbala'),
#         ('babil', 'Babil'),
#         ('wasit', 'Wasit'),
#         ('diwaniya', 'Diwaniya'),
#         ('diyala', 'Diyala'),
#         ('kirkuk', 'Kirkuk'),
#         ('ninawa', 'Ninawa'),
#         ('salah_al_din', 'Salah al-Din'),
#         ('duhok', 'Duhok'),
#         ('erbil', 'Erbil'),
#         ('sulaymaniyah', 'Sulaymaniyah'),
#         ('halabja', 'Halabja'),
#     ]
#
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='translate')
#     full_name = models.CharField(max_length=255)
#     email = models.EmailField()
#     phone = models.CharField(max_length=255)
#     address = models.CharField(max_length=255)
#     nearestPoint = models.CharField(max_length=255)
#     govern = models.CharField(max_length=20, choices=GOVERNORATE_CHOICES)
#
#
#     touch = models.BooleanField(default=False)
#     fees = models.CharField(max_length=100)
#     received = models.BooleanField(default=False)
#     submitted = models.BooleanField(default=False)
#
#
# class LangCourse(models.Model):
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='langcourse')
#     university = models.ForeignKey('University', on_delete=models.CASCADE, related_name='langcourse')
#     full_name = models.CharField(max_length=255)
#     email = models.EmailField()
#     phone = models.CharField(max_length=255)
#     passport = models.CharField(max_length=255)
#     traker = models.CharField(max_length=255)
#     pdf = models.FileField(upload_to='lang/')
#
#     touch = models.BooleanField(default=False)
#     fees = models.CharField(max_length=100)
#     submitted = models.BooleanField(default=False)
#     accepted = models.BooleanField(default=False)
#
# class Universityfees(models.Model):
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='fees')
#     university = models.ForeignKey('University', on_delete=models.CASCADE, related_name='fees')
#     full_name = models.CharField(max_length=255)
#     email = models.EmailField()
#     phone = models.CharField(max_length=255)
#     department = models.CharField(max_length=255)
#     univerFees = models.CharField(max_length=255)
#     kind = models.CharField(max_length=255)
#
#
#
#     touch = models.BooleanField(default=False)
#     payoff = models.BooleanField(default=False)
#     fees = models.CharField(max_length=100)
#     submitted = models.BooleanField(default=False)
#
#
# class Publish (models.Model):
#     user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='publish')
#     full_name = models.CharField(max_length=255)
#     email = models.EmailField()
#     phone = models.CharField(max_length=255)
#     department = models.CharField(max_length=255)
#     pages = models.CharField(max_length=255)
#     magazine = models.CharField(max_length=255)
#     mushref = models.CharField(max_length=255)
#     publishResearch = models.BooleanField(default=False)
#     time = models.DateTimeField(auto_now_add=True)
#     stilal = models.BooleanField(default=False)
#     international = models.BooleanField(default=False)
#
#
#     touch = models.BooleanField(default=False)
#     fees = models.CharField(max_length=100)
#     payoff = models.BooleanField(default=False)
#     submitted = models.BooleanField(default=False)
#

