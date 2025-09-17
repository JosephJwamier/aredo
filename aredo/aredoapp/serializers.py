from rest_framework import serializers
from .models import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Users
from django.utils import timezone

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
            email=validated_data['phone_number'],
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



class FormKindFieldSerializer(serializers.ModelSerializer):
    """Serializer for FormKindField model"""

    class Meta:
        model = FormKindField
        fields = [
            'id', 'field_name', 'is_required', 'display_name',
            'help_text', 'field_order'
        ]


class FormKindSerializer(serializers.ModelSerializer):
    """Serializer for FormKind model"""

    required_fields = FormKindFieldSerializer(many=True, read_only=True)
    applications_count = serializers.SerializerMethodField()

    class Meta:
        model = FormKind
        fields = [
            'id', 'name', 'manager', 'phone', 'is_active',
            'requires_university', 'requires_file_upload', 'icon',
             'required_fields', 'applications_count',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_applications_count(self, obj):
        """Get total number of applications for this form kind"""
        return obj.applications.count()


class FormKindListSerializer(serializers.ModelSerializer):
    """Simplified serializer for listing form kinds"""

    class Meta:
        model = FormKind
        fields = [
            'id', 'name', 'manager', 'phone', 'requires_university',
            'requires_file_upload', 'icon', 'display_order'
        ]


# Updated ApplicationForm serializer to work with FormKind
class ApplicationFormSerializer(serializers.ModelSerializer):
    """Base serializer for ApplicationForm with FormKind support"""

    kind_display = serializers.CharField(source='kind.manager', read_only=True)
    kind_name = serializers.CharField(source='kind.name', read_only=True)
    status_display = serializers.CharField(read_only=True)
    completion_percentage = serializers.SerializerMethodField()
    is_editable = serializers.BooleanField(read_only=True)
    university_name = serializers.CharField(source='university.name', read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id', 'kind', 'kind_display', 'kind_name', 'user', 'university',
            'university_name', 'full_name', 'email', 'phone', 'department',
            'fees', 'status_display', 'completion_percentage', 'is_editable',
            'touch', 'submitted', 'approved', 'accepted', 'received', 'payoff',
            'date_applied', 'date', 'updated_at'
        ]
        read_only_fields = [
            'user', 'date_applied', 'data', 'updated_at', 'status_display',
            'completion_percentage', 'is_editable', 'kind_display', 'kind_name',
            'university_name'
        ]

    def get_completion_percentage(self, obj):
        """Get form completion percentage"""
        return obj.get_completion_percentage()

    def validate_kind(self, value):
        """Validate that the form kind is active"""
        if not value.is_active:
            raise serializers.ValidationError("This form type is currently not available.")
        return value


class ApplicationFormPartialSerializer(ApplicationFormSerializer):
    """Serializer specifically for partial updates with relaxed validation"""

    class Meta(ApplicationFormSerializer.Meta):
        # Make all editable fields optional for partial updates
        extra_kwargs = {
            'kind': {'required': False},
            'university': {'required': False},
            'full_name': {'required': False},
            'email': {'required': False},
            'phone': {'required': False},
            'department': {'required': False},
            'fees': {'required': False},
        }

    def validate(self, attrs):
        """Lighter validation for partial updates"""
        instance = getattr(self, 'instance', None)

        # Check if form is editable
        if instance and not instance.is_editable:
            raise serializers.ValidationError(
                "This application form can no longer be edited."
            )

        # Validate individual fields if they're being updated
        if 'email' in attrs and attrs['email']:
            if not self._is_valid_email(attrs['email']):
                raise serializers.ValidationError({
                    'email': 'Enter a valid email address.'
                })

        if 'phone' in attrs and attrs['phone']:
            if not self._is_valid_phone(attrs['phone']):
                raise serializers.ValidationError({
                    'phone': 'Enter a valid phone number.'
                })


        return attrs

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
class ApplicantFormSerializer(serializers.ModelSerializer):
    """
    Applicant Form Serializer based on old Applicant model.

    Required fields: university, full_name, email, phone, degreenum, passport, degree,
                    department, deepdepartment, grad_univerBach, grad_univermaster, traker, pdf
    """
    images = ApplicationImageSerializer(many=True, read_only=True)
    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'university', 'full_name', 'email', 'phone',
            'degreenum', 'passport', 'degree', 'department', 'deepdepartment',
            'grad_univerBach', 'grad_univermaster', 'traker', 'pdf', 'fees',
            'touch', 'submitted', 'approved', 'accepted', 'date_applied',
            'images'
        ]
        read_only_fields = ['id', 'user', 'date_applied']


class CancelCodeFormSerializer(serializers.ModelSerializer):
    """
    Cancel Code Form Serializer based on old CancelCode model.

    Required fields: university, full_name, email, phone, traker, pdf
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id', 'kind','user', 'university', 'full_name', 'email', 'phone',
            'traker', 'pdf', 'fees', 'touch', 'submitted', 'approved',
            'images'
        ]
        read_only_fields = ['id', 'user']


class TranslateFormSerializer(serializers.ModelSerializer):
    """
    Translation Form Serializer based on old Translate model.

    Required fields: full_name, email, phone, address, nearestPoint, govern
    """

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'full_name', 'email', 'phone', 'address',
            'nearestPoint', 'govern', 'fees', 'touch', 'received', 'submitted'
        ]
        read_only_fields = ['id', 'user']


class LangCourseFormSerializer(serializers.ModelSerializer):
    """
    Language Course Form Serializer based on old LangCourse model.

    Required fields: university, full_name, email, phone, passport, traker, pdf
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'university', 'full_name', 'email', 'phone',
            'passport', 'traker', 'pdf', 'fees', 'touch', 'submitted', 'accepted',
            'images'
        ]
        read_only_fields = ['id', 'user']


class UniversityFeesFormSerializer(serializers.ModelSerializer):
    """
    University Fees Form Serializer based on old Universityfees model.

    Required fields: university, full_name, email, phone, department, univerFees, kind_fees
    """

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'university', 'full_name', 'email', 'phone',
            'department', 'univerFees', 'kind_fees', 'fees', 'touch',
            'payoff', 'submitted'
        ]
        read_only_fields = ['id', 'user']


class PublishFormSerializer(serializers.ModelSerializer):
    """
    Publish Research Form Serializer based on old Publish model.

    Required fields: full_name, email, phone, department, pages, magazine, mushref
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'full_name', 'email', 'phone', 'department',
            'pages', 'magazine', 'mushref', 'publishResearch', 'date',
            'stilal', 'international', 'fees', 'touch', 'payoff', 'submitted',
            'images'
        ]
        read_only_fields = ['id', 'user', 'data']



class Flight(serializers.ModelSerializer):
    """
        flight حجز تذكرة طيران
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'full_name', 'phone', 'passport' ,'govern','by'
            ,'date','notes','touch', 'payoff', 'submitted',
            'images'
        ]
        read_only_fields = ['id', 'user', 'data']


class HigherEducationFile(serializers.ModelSerializer):
    """
    open file in the higher education
    req :فتح ملف في وزارة التعليم
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'full_name', 'email', 'phone','touch', 'payoff',
            'images'
        ]
        read_only_fields = ['id', 'user']

class Rahgery(serializers.ModelSerializer):
    """
        استخراج كود راهكيري
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'full_name','email', 'phone', 'passport' , 'university', 'department', 'deepdepartment' ,
            'touch', 'payoff', 'submitted',
            'images'
        ]
        read_only_fields = ['id', 'user']


class Istalal(serializers.ModelSerializer):
    """
        استلال البحث
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'full_name','email', 'phone', 'pdf',
            'touch', 'payoff', 'submitted','images'

        ]
        read_only_fields = ['id', 'user']


class Delvary(serializers.ModelSerializer):
    """
        توصيل الوثائق داخل العراق
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'full_name','phone', 'nearestPoint','address','govern',
            'touch', 'payoff', 'submitted','images'

        ]
        read_only_fields = ['id', 'user']



class TranslateIraq(serializers.ModelSerializer):
    """
        الترجمة لكورس اللغة والوثيقة داخل العراق
    """
    images = ApplicationImageSerializer(many=True, read_only=True)

    class Meta:
        model = ApplicationForm
        fields = [
            'id','kind', 'user', 'full_name','phone', 'nearestPoint','address','govern',
            'touch', 'payoff', 'submitted','images'

        ]
        read_only_fields = ['id', 'user']

# Admin serializers
class ApplicationFormAdminSerializer(ApplicationFormSerializer):
    """Enhanced serializer for admin use with additional fields"""

    user_email = serializers.CharField(source='user.email', read_only=True)
    user_name = serializers.SerializerMethodField()

    class Meta(ApplicationFormSerializer.Meta):
        fields = ApplicationFormSerializer.Meta.fields + [
            'user_email', 'user_name',
            # Include all possible fields for admin view
            'degreenum', 'passport', 'degree', 'deepdepartment',
            'grad_univerBach', 'grad_univermaster', 'traker', 'pdf',
            'address', 'nearestPoint', 'govern',
            'pages', 'magazine', 'mushref', 'publishResearch',
            'stilal', 'international',
            'univerFees', 'kind_fees'
        ]

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


# Bulk operations serializer
class BulkStatusUpdateSerializer(serializers.Serializer):
    """Serializer for bulk status updates"""

    application_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1,
        max_length=100,
        help_text="List of application IDs to update"
    )
    status_updates = serializers.DictField(
        child=serializers.BooleanField(),
        help_text="Status fields to update (e.g., {'approved': True, 'accepted': False})"
    )

    def validate_status_updates(self, value):
        """Validate status update fields"""
        allowed_fields = ['touch', 'submitted', 'approved', 'accepted', 'received', 'payoff']
        invalid_fields = set(value.keys()) - set(allowed_fields)

        if invalid_fields:
            raise serializers.ValidationError(
                f"Invalid status fields: {', '.join(invalid_fields)}. "
                f"Allowed fields: {', '.join(allowed_fields)}"
            )

        return value



class ApplicationFormWithImagesSerializer(ApplicationFormSerializer):
    """Extended serializer that includes images"""
    images = ApplicationImageSerializer(many=True, read_only=True)
    image_count = serializers.SerializerMethodField()

    class Meta(ApplicationFormSerializer.Meta):
        fields = ApplicationFormSerializer.Meta.fields + ['images', 'image_count']

    def get_image_count(self, obj):
        return obj.images.count()
