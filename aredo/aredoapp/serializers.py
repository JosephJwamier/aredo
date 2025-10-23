from rest_framework import serializers
from .models import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Users
from django.utils import timezone
import re


class AdminUserCreateSerializer(serializers.ModelSerializer):
    """Serializer for admin to create users with staff/superuser permissions"""
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = Users
        fields = ['phone_number', 'name', 'password', 'password_confirm', 'is_staff', 'is_superuser']
        extra_kwargs = {
            'password': {'write_only': True},
            'is_staff': {'default': False},
            'is_superuser': {'default': False}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match")
        return attrs

    def create(self, validated_data):
        validated_data.pop('password_confirm')

        # Create user with permissions
        user = Users.objects.create_user(
            phone_number=validated_data['phone_number'],
            name=validated_data['name'],
            password=validated_data['password']
        )

        # Set permissions
        user.is_staff = validated_data.get('is_staff', False)
        user.is_superuser = validated_data.get('is_superuser', False)
        user.save()

        return user


class AdminUserUpdateSerializer(serializers.ModelSerializer):
    """Serializer for admin to update user permissions"""

    class Meta:
        model = Users
        fields = ['id', 'phone_number', 'name', 'is_staff', 'is_superuser', 'is_active']
        read_only_fields = ['id', 'phone_number']  # Don't allow email changes

    def validate(self, attrs):
        # Prevent admin from removing their own superuser status
        if self.instance and self.context['request'].user == self.instance:
            if not attrs.get('is_superuser', self.instance.is_superuser):
                raise serializers.ValidationError(
                    "You cannot remove your own superuser privileges"
                )
        return attrs


class AdminUserListSerializer(serializers.ModelSerializer):
    """Serializer for listing users with admin info"""

    class Meta:
        model = Users
        fields = ['id', 'phone_number', 'name', 'is_staff', 'is_superuser', 'is_active']



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'phone_number', 'name']

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['phone_number', 'name', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = Users.objects.create_user(
            phone_number=validated_data['phone_number'],
            name=validated_data['name'],
            password=validated_data['password']
        )
        return user


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)

        # Add custom user fields (excluding password)
        user = self.user
        data['user'] = {
            "id": user.id,
            "username": user.name,
            "phone_number": user.phone_number,
            "is_superuser": user.is_superuser,
            "is_staff": user.is_staff,

        }

        return data


class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Country
        fields = '__all__'


class UniversitySerializer(serializers.ModelSerializer):
    country = serializers.PrimaryKeyRelatedField(queryset=Country.objects.all())
    country_name = serializers.CharField(source='country.name', read_only=True)
    pdf = serializers.FileField(required=False, allow_null=True)

    class Meta:
        model = University
        fields = '__all__'

class NewsTypeSerializer(serializers.ModelSerializer):
    """Serializer for NewsType model"""
    news_count = serializers.SerializerMethodField()

    class Meta:
        model = NewsType
        fields = ['id', 'name', 'slug', 'description', 'color', 'is_active',
                  'created_at', 'updated_at', 'news_count']
        read_only_fields = ['slug', 'created_at', 'updated_at', 'news_count']

    def get_news_count(self, obj):
        """Get count of news for this type - now works with ForeignKey"""
        return obj.news_articles.count()


class NewsImageSerializer(serializers.ModelSerializer):
    """Serializer for NewsImage model"""
    file_size_human = serializers.ReadOnlyField()
    image_url = serializers.SerializerMethodField()

    class Meta:
        model = NewsImage
        fields = ['id', 'news', 'image', 'image_url', 'title',
                  'caption', 'order', 'is_active', 'uploaded_at', 'file_size_human']
        read_only_fields = ['uploaded_at', 'file_size_human']

    def get_image_url(self, obj):
        """Get full URL for image"""
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None


class NewsSerializer(serializers.ModelSerializer):
    """Main serializer for News model"""
    images = NewsImageSerializer(many=True, read_only=True)
    news_type_name = serializers.CharField(source='news_type.name', read_only=True)

    class Meta:
        model = News
        fields = ['id', 'title', 'content', 'news_type', 'news_type_name',
                  'created_at', 'updated_at', 'images']
        read_only_fields = ['created_at', 'updated_at']


class NewsCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating news articles"""

    class Meta:
        model = News
        fields = ['title', 'content', 'news_type']

    def validate_news_type(self, value):
        """Validate that news type is active"""
        if not value.is_active:
            raise serializers.ValidationError("Selected news type is not active")
        return value


class FormKindSerializer(serializers.ModelSerializer):
    """Serializer for FormKind model"""

    applications_count = serializers.SerializerMethodField()
    field_requirements = serializers.SerializerMethodField()

    class Meta:
        model = FormKind
        fields = '__all__'
        read_only_fields = ['created_at', 'updated_at']

    def get_applications_count(self, obj):
        """Get total number of applications for this form kind"""
        return obj.applications.count()

    def get_field_requirements(self, obj):
        """Get user-fillable field requirements for this form kind (exclude status/workflow fields)"""
        # Only include fields that users can actually fill out
        user_field_mapping = {
            'university': obj.university,
            'full_name': obj.full_name,
            'email': obj.email,
            'phonefield': obj.phonefield,
            'notes': obj.notes,
            'department': obj.department,
            'fees': obj.fees,
            'degreenum': obj.degreenum,
            'passport': obj.passport,
            'degree': obj.degree,
            'deepdepartment': obj.deepdepartment,
            'grad_univerBach': obj.grad_univerBach,
            'grad_univermaster': obj.grad_univermaster,
            'traker': obj.traker,
            'pdf': obj.pdf,
            'address': obj.address,
            'nearestPoint': obj.nearestPoint,
            'govern': obj.govern,
            'by': obj.by,
            'pages': obj.pages,
            'magazine': obj.magazine,
            'mushref': obj.mushref,
            'publishResearch': obj.publishResearch,
            'stilal': obj.stilal,
            'international': obj.international,
            'univerFees': obj.univerFees,
            'kind_fees': obj.kind_fees,
            'touch': obj.touch,
            'submitted': obj.submitted,
            'approved': obj.approved,
            'accepted': obj.accepted,
            'received': obj.received,
            'payoff': obj.payoff,
            'date_applied': obj.date_applied,
            'date': obj.date,
        }

        required_fields = [field for field, required in user_field_mapping.items() if required]
        optional_fields = [field for field, required in user_field_mapping.items() if not required]

        return {
            'required': required_fields,
            'optional': optional_fields,
            'status_info': 'Status fields (touch, submitted, approved, etc.) are managed by the system'
        }

class FormKindListSerializer(serializers.ModelSerializer):
    """Simplified serializer for listing form kinds"""

    class Meta:
        model = FormKind
        fields = '__all__'


class DynamicFormValidationMixin:
    """Mixin to provide dynamic form validation based on FormKind"""

    def validate_based_on_kind(self, attrs):
        """Validate form data based on FormKind requirements"""
        kind = attrs.get('kind')
        if not kind:
            if self.instance:
                kind = self.instance.kind
            else:
                raise serializers.ValidationError("Form kind is required")

        # Check if form kind is active
        if not kind.is_active:
            raise serializers.ValidationError("This form type is currently not available.")

        errors = {}

        # Get user-fillable field requirements (exclude system/status fields)
        user_field_requirements = self.get_user_field_requirements_from_kind(kind)
        required_fields = [field for field, is_required in user_field_requirements.items() if is_required]

        # NOTE: We no longer check for unrequired fields here
        # That's handled in to_internal_value() which silently filters them out

        # Validate required fields
        for field_name in required_fields:
            # Map FormKind field names to ApplicationForm field names
            mapped_field = self.map_kind_field_to_form_field(field_name)

            if mapped_field in attrs:
                value = attrs[mapped_field]
            elif self.instance:
                value = getattr(self.instance, mapped_field, None)
            else:
                value = None

            # Check if required field is empty
            if not value and value != 0 and value is not False:
                errors[mapped_field] = f"This field is required for {kind.manager} applications"

        # Perform kind-specific validation
        kind_errors = self.validate_by_specific_kind(attrs, kind)
        errors.update(kind_errors)

        if errors:
            raise serializers.ValidationError(errors)

        return attrs

    def is_admin_user(self):
        """Check if the current user is an admin"""
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            return request.user.is_staff or request.user.is_superuser
        return False

    def get_user_field_requirements_from_kind(self, kind):
        """Extract ALL field requirements INCLUDING status fields from FormKind instance"""
        # Map of ALL FormKind boolean fields to their requirement status
        user_field_mappings = {
            'university': kind.university,
            'full_name': kind.full_name,
            'email': kind.email,
            'phone': kind.phone,
            'notes': kind.notes,
            'department': kind.department,
            'fees': kind.fees,
            'degreenum': kind.degreenum,
            'passport': kind.passport,
            'degree': kind.degree,
            'deepdepartment': kind.deepdepartment,
            'grad_univerBach': kind.grad_univerBach,
            'grad_univermaster': kind.grad_univermaster,
            'traker': kind.traker,
            'pdf': kind.pdf,
            'address': kind.address,
            'nearestPoint': kind.nearestPoint,
            'govern': kind.govern,
            'by': kind.by,
            'pages': kind.pages,
            'magazine': kind.magazine,
            'mushref': kind.mushref,
            'publishResearch': kind.publishResearch,
            'stilal': kind.stilal,
            'international': kind.international,
            'univerFees': kind.univerFees,
            'kind_fees': kind.kind_fees,
            'date': kind.date,
            # STATUS FIELDS - Only include if user is admin
            'touch': kind.touch if self.is_admin_user() else False,
            'submitted': kind.submitted if self.is_admin_user() else False,
            'approved': kind.approved if self.is_admin_user() else False,
            'accepted': kind.accepted if self.is_admin_user() else False,
            'received': kind.received if self.is_admin_user() else False,
            'payoff': kind.payoff if self.is_admin_user() else False,
            'date_applied': kind.date_applied ,
        }

        return user_field_mappings

    def get_all_field_requirements_from_kind(self, kind):
        """Extract all field requirements (including status fields) from FormKind instance - for display purposes"""
        # This method is kept for backward compatibility and display purposes
        # but should not be used for validation
        all_field_mappings = {
            'university': kind.university,
            'full_name': kind.full_name,
            'email': kind.email,
            'phone': kind.phone,
            'notes': kind.notes,
            'department': kind.department,
            'fees': kind.fees,
            'degreenum': kind.degreenum,
            'passport': kind.passport,
            'degree': kind.degree,
            'deepdepartment': kind.deepdepartment,
            'grad_univerBach': kind.grad_univerBach,
            'grad_univermaster': kind.grad_univermaster,
            'traker': kind.traker,
            'pdf': kind.pdf,
            'address': kind.address,
            'nearestPoint': kind.nearestPoint,
            'govern': kind.govern,
            'by': kind.by,
            'pages': kind.pages,
            'magazine': kind.magazine,
            'mushref': kind.mushref,
            'publishResearch': kind.publishResearch,
            'stilal': kind.stilal,
            'international': kind.international,
            'univerFees': kind.univerFees,
            'touch': kind.touch,
            'kind_fees': kind.kind_fees,
            'submitted': kind.submitted,
            'approved': kind.approved,
            'accepted': kind.accepted,
            'received': kind.received,
            'payoff': kind.payoff,
            'date_applied': kind.date_applied,
            'date': kind.date,
        }

        return all_field_mappings

    def get_required_fields_from_kind(self, kind):
        """Extract required field names from FormKind instance (user-fillable fields only)"""
        user_requirements = self.get_user_field_requirements_from_kind(kind)
        return [field_name for field_name, is_required in user_requirements.items() if is_required]

    def map_kind_field_to_form_field(self, kind_field_name):
        """Map FormKind field names to ApplicationForm field names"""
        field_mapping = {
            'phone': 'phone',  # FormKind uses 'phonefield', ApplicationForm uses 'phone'
        }

        return field_mapping.get(kind_field_name, kind_field_name)

    def validate_by_specific_kind(self, attrs, kind):
        """Perform validation specific to certain form kinds"""
        errors = {}

        # Get current values (either from attrs or existing instance)
        def get_field_value(field_name):
            if field_name in attrs:
                return attrs[field_name]
            elif self.instance:
                return getattr(self.instance, field_name, None)
            return None

        # Applicant-specific validations
        if kind.name.lower() == 'applicant':
            degree = get_field_value('degree')
            grad_univerBach = get_field_value('grad_univerBach')
            grad_univermaster = get_field_value('grad_univermaster')

            if degree == 'master' and kind.grad_univerBach and not grad_univerBach:
                errors['grad_univerBach'] = 'Bachelor graduation university is required for Master degree applications'

            if degree == 'phd' and kind.grad_univermaster and not grad_univermaster:
                errors['grad_univermaster'] = 'Master graduation university is required for PhD applications'

        # University Fees specific validations
        elif kind.name.lower() == 'universityfees':
            univer_fees = get_field_value('univerFees')
            if univer_fees and not str(univer_fees).replace('.', '').isdigit():
                errors['univerFees'] = 'University fees must be a valid number'

        # Flight specific validations
        elif kind.name.lower() == 'flight':
            by = get_field_value('by')
            if kind.by and not by:
                errors['by'] = 'Transportation method is required for flight applications'

        # Translate specific validations
        elif kind.name.lower() == 'translate':
            govern = get_field_value('govern')
            address = get_field_value('address')

            if kind.govern and not govern:
                errors['govern'] = 'Governorate is required for translate applications'
            if kind.address and not address:
                errors['address'] = 'Address is required for translate applications'

        # Publish specific validations
        elif kind.name.lower() == 'publish':
            pages = get_field_value('pages')
            magazine = get_field_value('magazine')

            if kind.pages and not pages:
                errors['pages'] = 'Number of pages is required for publish applications'
            if kind.magazine and not magazine:
                errors['magazine'] = 'Magazine name is required for publish applications'

        return errors

class ApplicationFormSerializer(DynamicFormValidationMixin, serializers.ModelSerializer):
    """Enhanced ApplicationForm serializer with dynamic validation and field filtering"""

    kind_display = serializers.CharField(source='kind.manager', read_only=True)
    kind_name = serializers.CharField(source='kind.name', read_only=True)
    status_display = serializers.CharField(read_only=True)
    completion_percentage = serializers.SerializerMethodField()
    is_editable = serializers.BooleanField(read_only=True)

    class Meta:
        model = ApplicationForm
        fields = '__all__'
        read_only_fields = [
            'user', 'date_applied', 'created_at', 'updated_at', 'status_display',
            'completion_percentage', 'is_editable', 'kind_display', 'kind_name'
        ]

    def to_internal_value(self, data):
        """Override to filter out unrequired fields before validation"""
        # Force status fields to False for non-admin users
        if not self.is_admin_user():
            status_fields = ['touch', 'submitted', 'approved', 'accepted', 'received', 'payoff']
            for field in status_fields:
                data[field] = False

        # Get the form kind from data or instance
        kind = None
        if 'kind' in data:
            try:
                from .models import FormKind  # Import here to avoid circular imports
                kind = FormKind.objects.get(id=data['kind'])
            except (FormKind.DoesNotExist, ValueError, TypeError):
                # Let the regular validation handle this error
                pass
        elif self.instance and self.instance.kind:
            kind = self.instance.kind

        if kind:
            # Get allowed user-fillable fields for this form kind (exclude status fields)
            user_field_requirements = self.get_user_field_requirements_from_kind(kind)
            allowed_form_fields = list(user_field_requirements.keys())

            # Add system fields that are always allowed
            system_fields = ['kind', 'user', 'id', 'created_at', 'updated_at', 'date_applied']
            allowed_form_fields.extend(system_fields)

            # Map to ApplicationForm field names (use set for O(1) lookup)
            mapped_allowed_fields = {self.map_kind_field_to_form_field(field) for field in allowed_form_fields}

            # Filter out unrequired fields SILENTLY (no error)
            filtered_data = {
                field_name: value
                for field_name, value in data.items()
                if field_name in mapped_allowed_fields
            }

            # Use filtered data for validation
            data = filtered_data

        return super().to_internal_value(data)

    def get_completion_percentage(self, obj):
        """Get form completion percentage based on kind requirements"""
        if not obj.kind:
            return 0

        required_fields = self.get_required_fields_from_kind(obj.kind)
        if not required_fields:
            return 100

        completed_fields = 0
        for field_name in required_fields:
            mapped_field = self.map_kind_field_to_form_field(field_name)
            field_value = getattr(obj, mapped_field, None)

            # Consider field completed if it has a value (including False for boolean fields)
            if field_value or field_value is False:
                completed_fields += 1

        return int((completed_fields / len(required_fields)) * 100) if required_fields else 100

    def get_required_fields(self, obj):
        """Get list of required field names for this form's kind (user-fillable only)"""
        if not obj.kind:
            return []

        required_fields = self.get_required_fields_from_kind(obj.kind)
        return [self.map_kind_field_to_form_field(field) for field in required_fields]

    def get_allowed_fields(self, obj):
        """Get list of all allowed field names for this form's kind (user-fillable only)"""
        if not obj.kind:
            return []

        user_requirements = self.get_user_field_requirements_from_kind(obj.kind)
        return [self.map_kind_field_to_form_field(field) for field in user_requirements.keys()]

    def validate(self, attrs):
        """Main validation method"""
        # Get the form kind
        kind = attrs.get('kind') or (self.instance.kind if self.instance else None)

        if kind:
            # Get required fields for this form kind
            required_fields = self.get_required_fields_from_kind(kind)

            # Check for missing required fields
            missing_fields = []
            for field_name in required_fields:
                mapped_field = self.map_kind_field_to_form_field(field_name)

                # Check if field exists in attrs or instance (for partial updates)
                field_value = attrs.get(mapped_field)
                if field_value is None and self.instance:
                    field_value = getattr(self.instance, mapped_field, None)

                # Field is missing if it's None or empty string
                if field_value is None or field_value == '':
                    missing_fields.append(mapped_field)

            # Raise error if required fields are missing
            if missing_fields:
                errors = {
                    field: f"This field is required for {kind.name} applications"
                    for field in missing_fields
                }
                raise serializers.ValidationError(errors)

        # Additional custom validations
        attrs = self.validate_email_format(attrs)

        return attrs

    def validate_email_format(self, attrs):
        """Validate email format if email is provided"""
        email = attrs.get('email')
        if email:
            # Basic email validation (Django's EmailField handles this, but we can add custom rules)
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            if not re.match(email_pattern, email):
                raise serializers.ValidationError({'email': 'Enter a valid email address.'})

        return attrs

class ApplicationFormPartialSerializer(DynamicFormValidationMixin, serializers.ModelSerializer):
    """Serializer for partial updates with conditional validation and field filtering"""

    class Meta:
        model = ApplicationForm
        fields = '__all__'

        read_only_fields = [
            'user', 'date_applied', 'created_at', 'updated_at'
        ]

    def to_internal_value(self, data):
        """Override to filter out unrequired fields before validation"""
        # Get the form kind from instance (partial updates always have an instance)
        kind = None
        if self.instance and self.instance.kind:
            kind = self.instance.kind
        elif 'kind' in data:
            try:
                from .models import FormKind
                kind = FormKind.objects.get(id=data['kind'])
            except (FormKind.DoesNotExist, ValueError):
                pass

        if kind:
            # Get allowed fields for this form kind
            all_field_requirements = self.get_all_field_requirements_from_kind(kind)
            allowed_form_fields = list(all_field_requirements.keys())

            # Add system fields that are always allowed
            system_fields = ['kind', 'user', 'id', 'created_at', 'updated_at', 'date_applied']
            allowed_form_fields.extend(system_fields)

            # Map to ApplicationForm field names
            mapped_allowed_fields = [self.map_kind_field_to_form_field(field) for field in allowed_form_fields]


            # Filter out unrequired fields
            filtered_data = {}
            rejected_fields = []

            for field_name, value in data.items():
                if field_name in mapped_allowed_fields:
                    filtered_data[field_name] = value
                else:
                    rejected_fields.append(field_name)

            # If there are rejected fields, raise validation error immediately
            if rejected_fields:
                errors = {}
                for field_name in rejected_fields:
                    errors[field_name] = f"This field is not allowed for {kind.manager} applications"
                raise serializers.ValidationError(errors)

            # Use filtered data for validation
            data = filtered_data

        return super().to_internal_value(data)

    def validate(self, attrs):
        """Validate partial updates - only validate if we have enough data or on final submission"""
        # For partial updates, we might want to skip some validations
        # unless the form is being submitted

        if attrs.get('submitted', False) or (self.instance and self.instance.submitted):
            # If form is being submitted, do full validation including unrequired field checking
            attrs = self.validate_based_on_kind(attrs)
        else:
            # For draft saves, only check for unrequired fields and basic validation
            kind = attrs.get('kind') or (self.instance.kind if self.instance else None)
            if kind:
                if not kind.is_active:
                    raise serializers.ValidationError("This form type is currently not available.")

                # Still check for unrequired fields even in draft mode
                all_field_requirements = self.get_all_field_requirements_from_kind(kind)
                allowed_form_fields = list(all_field_requirements.keys())
                system_fields = ['kind', 'user', 'id', 'created_at', 'updated_at', 'date_applied']
                allowed_form_fields.extend(system_fields)
                mapped_allowed_fields = [self.map_kind_field_to_form_field(field) for field in allowed_form_fields]

                # Check for unrequired fields
                unrequired_fields = []
                for field_name in attrs.keys():
                    if field_name not in mapped_allowed_fields:
                        unrequired_fields.append(field_name)

                if unrequired_fields:
                    errors = {}
                    for field_name in unrequired_fields:
                        errors[field_name] = f"This field is not allowed for {kind.manager} applications"
                    raise serializers.ValidationError(errors)

        return super().validate(attrs)




class ApplicationImageSerializer(serializers.ModelSerializer):
    image_url = serializers.SerializerMethodField()
    file_size_mb = serializers.ReadOnlyField()

    class Meta:
        model = ApplicationImage
        fields = [
            'id', 'image', 'image_url', 'image_type', 'description',
            'uploaded_at', 'file_size', 'file_size_mb', 'width', 'height'
        ]
        read_only_fields = ['id', 'uploaded_at', 'file_size', 'width', 'height']

    def get_image_url(self, obj):
        if obj.image:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.image.url)
            return obj.image.url
        return None


# Specific serializers based on your old models - only required fields
# class ApplicantFormSerializer(serializers.ModelSerializer):
#     """
#     Applicant Form Serializer based on old Applicant model.
#
#     Required fields: university, full_name, email, phone, degreenum, passport, degree,
#                     department, deepdepartment, grad_univerBach, grad_univermaster, traker, pdf
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'university', 'full_name', 'email', 'phone',
#             'degreenum', 'passport', 'degree', 'department', 'deepdepartment',
#             'grad_univerBach', 'grad_univermaster', 'traker', 'pdf', 'fees',
#             'touch', 'submitted', 'approved', 'accepted', 'date_applied',
#             'images'
#         ]
#         read_only_fields = ['id', 'user', 'date_applied']


# Admin serializers
class ApplicationFormAdminSerializer(ApplicationFormSerializer):
    """Enhanced serializer for admin use with additional fields"""

    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()

    class Meta(ApplicationFormSerializer.Meta):
        fields ='__all__'

    def get_user_name(self, obj):
        """Get user's display name"""
        if hasattr(obj.user, 'get_full_name'):
            return obj.user.get_full_name()
        elif hasattr(obj.user, 'username'):
            return obj.user.username
        else:
            return str(obj.user)


class FormKindStatsSerializer(serializers.Serializer):
    """Serializer for form kind statistics"""

    kind_name = serializers.CharField()
    kind_manager = serializers.CharField()
    total_applications = serializers.IntegerField()
    submitted_applications = serializers.IntegerField()
    approved_applications = serializers.IntegerField()
    accepted_applications = serializers.IntegerField()
    received_applications = serializers.IntegerField()
    average_completion_time = serializers.FloatField(allow_null=True)



class ApplicationFormWithImagesSerializer(ApplicationFormSerializer):
    """Extended serializer that includes images"""
    images = ApplicationImageSerializer(many=True, read_only=True)
    image_count = serializers.SerializerMethodField()

    class Meta(ApplicationFormSerializer.Meta):
        fields = '__all__'

    def get_image_count(self, obj):
        return obj.images.count()

#
# # Bulk operations serializer
# class BulkStatusUpdateSerializer(serializers.Serializer):
#     """Serializer for bulk status updates"""
#
#     application_ids = serializers.ListField(
#         child=serializers.UUIDField(),
#         min_length=1,
#         max_length=100,
#         help_text="List of application IDs to update"
#     )
#     status_updates = serializers.DictField(
#         child=serializers.BooleanField(),
#         help_text="Status fields to update (e.g., {'approved': True, 'accepted': False})"
#     )
#
#     def validate_status_updates(self, value):
#         """Validate status update fields"""
#         allowed_fields = ['touch', 'submitted', 'approved', 'accepted', 'received', 'payoff']
#         invalid_fields = set(value.keys()) - set(allowed_fields)
#
#         if invalid_fields:
#             raise serializers.ValidationError(
#                 f"Invalid status fields: {', '.join(invalid_fields)}. "
#                 f"Allowed fields: {', '.join(allowed_fields)}"
#             )
#
#         return value
#


#
# class CancelCodeFormSerializer(serializers.ModelSerializer):
#     """
#     Cancel Code Form Serializer based on old CancelCode model.
#
#     Required fields: university, full_name, email, phone, traker, pdf
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id', 'kind','user', 'university', 'full_name', 'email', 'phone',
#             'traker', 'pdf', 'fees', 'touch', 'submitted', 'approved',
#             'images'
#         ]
#         read_only_fields = ['id', 'user']
#
#
# class TranslateFormSerializer(serializers.ModelSerializer):
#     """
#     Translation Form Serializer based on old Translate model.
#
#     Required fields: full_name, email, phone, address, nearestPoint, govern
#     """
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'full_name', 'email', 'phone', 'address',
#             'nearestPoint', 'govern', 'fees', 'touch', 'received', 'submitted'
#         ]
#         read_only_fields = ['id', 'user']
#
#
# class LangCourseFormSerializer(serializers.ModelSerializer):
#     """
#     Language Course Form Serializer based on old LangCourse model.
#
#     Required fields: university, full_name, email, phone, passport, traker, pdf
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'university', 'full_name', 'email', 'phone',
#             'passport', 'traker', 'pdf', 'fees', 'touch', 'submitted', 'accepted',
#             'images'
#         ]
#         read_only_fields = ['id', 'user']
#
#
# class UniversityFeesFormSerializer(serializers.ModelSerializer):
#     """
#     University Fees Form Serializer based on old Universityfees model.
#
#     Required fields: university, full_name, email, phone, department, univerFees, kind_fees
#     """
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'university', 'full_name', 'email', 'phone',
#             'department', 'univerFees', 'kind_fees', 'fees', 'touch',
#             'payoff', 'submitted'
#         ]
#         read_only_fields = ['id', 'user']
#
#
# class PublishFormSerializer(serializers.ModelSerializer):
#     """
#     Publish Research Form Serializer based on old Publish model.
#
#     Required fields: full_name, email, phone, department, pages, magazine, mushref
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'full_name', 'email', 'phone', 'department',
#             'pages', 'magazine', 'mushref', 'publishResearch', 'date',
#             'stilal', 'international', 'fees', 'touch', 'payoff', 'submitted',
#             'images'
#         ]
#         read_only_fields = ['id', 'user', 'data']
#
#
#
# class Flight(serializers.ModelSerializer):
#     """
#         flight حجز تذكرة طيران
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'full_name', 'phone', 'passport' ,'govern','by'
#             ,'date','notes','touch', 'payoff', 'submitted',
#             'images'
#         ]
#         read_only_fields = ['id', 'user', 'data']
#
#
# class HigherEducationFile(serializers.ModelSerializer):
#     """
#     open file in the higher education
#     req :فتح ملف في وزارة التعليم
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'full_name', 'email', 'phone','touch', 'payoff',
#             'images'
#         ]
#         read_only_fields = ['id', 'user']
#
# class Rahgery(serializers.ModelSerializer):
#     """
#         استخراج كود راهكيري
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'full_name','email', 'phone', 'passport' , 'university', 'department', 'deepdepartment' ,
#             'touch', 'payoff', 'submitted',
#             'images'
#         ]
#         read_only_fields = ['id', 'user']
#
#
# class Istalal(serializers.ModelSerializer):
#     """
#         استلال البحث
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'full_name','email', 'phone', 'pdf',
#             'touch', 'payoff', 'submitted','images'
#
#         ]
#         read_only_fields = ['id', 'user']
#
#
# class Delvary(serializers.ModelSerializer):
#     """
#         توصيل الوثائق داخل العراق
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'full_name','phone', 'nearestPoint','address','govern',
#             'touch', 'payoff', 'submitted','images'
#
#         ]
#         read_only_fields = ['id', 'user']
#
#
#
# class TranslateIraq(serializers.ModelSerializer):
#     """
#         الترجمة لكورس اللغة والوثيقة داخل العراق
#     """
#     images = ApplicationImageSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = ApplicationForm
#         fields = [
#             'id','kind', 'user', 'full_name','phone', 'nearestPoint','address','govern',
#             'touch', 'payoff', 'submitted','images'
#
#         ]
#         read_only_fields = ['id', 'user']
