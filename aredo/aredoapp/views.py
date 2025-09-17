# Create your views here.
from datetime import timedelta
from django.utils.text import slugify
from django.core.files.storage import default_storage
from django.db import transaction
from rest_framework.exceptions import NotFound, ValidationError
from django.http import Http404
from django_filters.rest_framework import DjangoFilterBackend
from .filters import *
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import filters
from django.utils import timezone
from rest_framework.permissions import IsAdminUser

from .serializers import *
from rest_framework.views import APIView
from rest_framework import generics

from rest_framework.decorators import api_view, permission_classes

from django.shortcuts import get_object_or_404

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import *
from .serializers import (
    ApplicationFormSerializer, ApplicantFormSerializer, CancelCodeFormSerializer,
    TranslateFormSerializer, LangCourseFormSerializer,
    UniversityFeesFormSerializer, PublishFormSerializer
)

from rest_framework.pagination import PageNumberPagination

from rest_framework.parsers import MultiPartParser, FormParser



class CustomPageNumberPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'count': self.page.paginator.count,
            'total_pages': self.page.paginator.num_pages,
            'current_page': self.page.number,
            'page_size': self.page_size,
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'results': data
        })


class IsSuperUserPermission(permissions.BasePermission):
    """Custom permission to only allow superusers to access this view."""

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser


class AdminUserCreateView(generics.CreateAPIView):
    """Create users with staff/superuser permissions - Superuser only"""
    queryset = Users.objects.all()
    serializer_class = AdminUserCreateSerializer
    permission_classes = [IsSuperUserPermission]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({
            'message': 'User created successfully',
            'user': AdminUserListSerializer(user).data
        }, status=status.HTTP_201_CREATED)


class AdminUserListView(generics.ListAPIView):
    """List all users with admin info - Superuser only"""
    queryset = Users.objects.all()
    serializer_class = AdminUserListSerializer
    permission_classes = [IsSuperUserPermission]
    pagination_class = CustomPageNumberPagination


class AdminUserUpdateView(generics.UpdateAPIView):
    """Update user permissions - Superuser only"""
    queryset = Users.objects.all()
    serializer_class = AdminUserUpdateSerializer
    permission_classes = [IsSuperUserPermission]
    lookup_field = 'id'

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({
            'message': 'User updated successfully',
            'user': AdminUserListSerializer(user).data
        })


class AdminUserDetailView(generics.RetrieveAPIView):
    """Get user details - Superuser only"""
    queryset = Users.objects.all()
    serializer_class = AdminUserListSerializer
    permission_classes = [IsSuperUserPermission]
    lookup_field = 'id'


@api_view(['POST'])
@permission_classes([IsSuperUserPermission])
def toggle_user_status(request, user_id):
    """Toggle user active status"""
    user = get_object_or_404(Users, id=user_id)

    # Prevent admin from deactivating themselves
    if request.user == user:
        return Response({
            'error': 'You cannot deactivate your own account'
        }, status=status.HTTP_400_BAD_REQUEST)

    user.is_active = not user.is_active
    user.save()

    return Response({
        'message': f'User {"activated" if user.is_active else "deactivated"} successfully',
        'user': AdminUserListSerializer(user).data
    })


# Register endpoint
class RegisterView(generics.CreateAPIView):
    queryset = Users.objects.all()
    serializer_class = RegisterSerializer


# Logout endpoint
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()  # blacklist the refresh token
            return Response({"detail": "Logout successful"}, status=200)
        except Exception as e:
            return Response({"error": str(e)}, status=400)


class CustomErrorMixin:
    """Mixin to handle custom error responses"""

    def handle_exception(self, exc):
        """Override to return custom error format"""
        if isinstance(exc, Http404) or isinstance(exc, NotFound):
            custom_response = {
                "success": False,
                "error": {
                    "message": str(exc),
                    "status_code": 404
                }
            }
            return Response(custom_response, status=status.HTTP_404_NOT_FOUND)

        if isinstance(exc, ValidationError):
            custom_response = {
                "success": False,
                "error": {
                    "message": "Validation failed",
                    "details": exc.detail,
                    "status_code": 400
                }
            }
            return Response(custom_response, status=status.HTTP_400_BAD_REQUEST)

        # For other exceptions, use default handling
        return super().handle_exception(exc)


class CustomResponseMixin:
    """Mixin to standardize API response format"""

    def get_success_response(self, data, message, status_code=status.HTTP_200_OK):
        return Response({
            "success": True,
            "message": message,
            "data": data
        }, status=status_code)

    def get_error_response(self, message, status_code=status.HTTP_400_BAD_REQUEST):
        return Response({
            "success": False,
            "message": message,
            "data": None
        }, status=status_code)


class CountryListCreateView(CustomErrorMixin,generics.ListCreateAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer
    permission_classes = [IsAdminUser]
    pagination_class = CustomPageNumberPagination

    def list(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().list(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Countries retrieved successfully",
            "data": response.data
        }

        return Response(custom_response, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().create(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Country created successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)


class CountryRetrieveUpdateDestroyView(CustomErrorMixin,generics.RetrieveUpdateDestroyAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer
    permission_classes = [IsAdminUser]

    def retrieve(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().retrieve(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Country retrieved successfully",
            "data": response.data
        }

        return Response(custom_response, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().update(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Country updated successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)

    def partial_update(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().partial_update(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Country updated successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)

    def destroy(self, request, *args, **kwargs):
        # Get the default response from parent class
        super().destroy(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Country deleted successfully",
            "data": None
        }

        return Response(custom_response, status=status.HTTP_200_OK)


class UniversityViewSet(CustomErrorMixin,viewsets.ModelViewSet):
    queryset = University.objects.all()
    serializer_class = UniversitySerializer
    pagination_class = CustomPageNumberPagination
    parser_classes = [MultiPartParser, FormParser]

    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.AllowAny()]  # Anyone can view
        return [permissions.IsAdminUser()]  # Only admin can add/delete/edit

    def list(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().list(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Universities retrieved successfully",
            "data": response.data
        }

        return Response(custom_response, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().retrieve(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "University retrieved successfully",
            "data": response.data
        }

        return Response(custom_response, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().create(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "University created successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)

    def update(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().update(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "University updated successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)

    def partial_update(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().partial_update(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "University updated successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)

    def destroy(self, request, *args, **kwargs):
        # Get the default response from parent class
        super().destroy(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "University deleted successfully",
            "data": None
        }

        return Response(custom_response, status=status.HTTP_200_OK)



class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


# Form Kind Management Views
class FormKindViewSet(CustomErrorMixin, viewsets.ModelViewSet):
    """CRUD operations for Form Kinds - Admin only for modifications"""
    queryset = FormKind.objects.all()
    serializer_class = FormKindSerializer
    pagination_class = CustomPageNumberPagination

    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.AllowAny()]
        return [IsAdminUser()]

    def list(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().list(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Form kinds retrieved successfully",
            "data": response.data
        }

        return Response(custom_response, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().retrieve(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Form kind retrieved successfully",
            "data": response.data
        }

        return Response(custom_response, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().create(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Form kind created successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)

    def update(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().update(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Form kind updated successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)

    def partial_update(self, request, *args, **kwargs):
        # Get the default response from parent class
        response = super().partial_update(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Form kind updated successfully",
            "data": response.data
        }

        return Response(custom_response, status=response.status_code)

    def destroy(self, request, *args, **kwargs):
        # Get the default response from parent class
        super().destroy(request, *args, **kwargs)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Form kind deleted successfully",
            "data": None
        }

        return Response(custom_response, status=status.HTTP_200_OK)

    @swagger_auto_schema(
        method='get',
        responses={200: FormKindSerializer(many=True)},
        operation_description="Get all active form kinds available for applications",
        tags=['Form Kinds'],
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ]
    )
    @action(detail=False, methods=['get'], url_path='active')
    def active_kinds(self, request):
        """Get only active form kinds with pagination"""
        active_kinds = FormKind.get_active_kinds()

        # Apply pagination
        page = self.paginate_queryset(active_kinds)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            paginated_response = self.get_paginated_response(serializer.data)

            # Wrap in custom format
            custom_response = {
                "success": True,
                "message": "Active form kinds retrieved successfully",
                "data": paginated_response.data
            }

            return Response(custom_response, status=status.HTTP_200_OK)

        serializer = self.get_serializer(active_kinds, many=True)

        # Wrap in custom format
        custom_response = {
            "success": True,
            "message": "Active form kinds retrieved successfully",
            "data": {
                'count': active_kinds.count(),
                'results': serializer.data
            }
        }

        return Response(custom_response, status=status.HTTP_200_OK)


class ApplicantViewSet(CustomErrorMixin,viewsets.ModelViewSet):
    queryset = ApplicationForm.objects.all()
    serializer_class = ApplicationFormSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

        # Helper methods to reduce code duplication

    def _create_form_by_code(self, request, kind_name, serializer_class):
        """Helper method to create forms of specific type using FormKind code"""
        try:
            form_kind = FormKind.objects.get(name=kind_name, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{kind_name}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = request.data.copy()
        data['kind'] = form_kind.id  # Use FormKind ID instead of code
        serializer = serializer_class(data=data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _list_forms_by_code(self, request, kind_name, serializer_class):
        """Helper method to list forms of specific type using FormKind code with pagination"""
        try:
            form_kind = FormKind.objects.get(name=kind_name, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{kind_name}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = self.get_queryset().filter(kind=form_kind)

        # Apply pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = serializer_class(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = serializer_class(queryset, many=True)
        return Response({
            'count': queryset.count(),
            'results': serializer.data
        })

    # Add parsers for file uploads at class level
    parser_classes = [MultiPartParser, FormParser]

    def generate_image_path(self, application, original_filename, image_type='general'):
        """
        Generate structured path: form_kind/username/date/image_type_timestamp.ext
        Example: applicant/john_doe/2025-08-08/passport_20250808_143022.jpg
        """
        # Get file extension
        file_ext = os.path.splitext(original_filename)[1].lower()

        # Create safe username (slug format)
        safe_username = slugify(application.user.name)

        # Get form kind code
        form_kind = application.kind.name if application.kind else 'unknown'

        # Get current date
        current_date = datetime.now()
        date_str = current_date.strftime('%Y-%m-%d')
        timestamp = current_date.strftime('%Y%m%d_%H%M%S_%f')[:17]  # Include microseconds for uniqueness

        # Create structured path
        custom_path = f"application_images/{form_kind}/{safe_username}/{date_str}/{image_type}_{timestamp}{file_ext}"

        return custom_path

    def handle_image_uploads(self, application, request):
        """Helper method to handle image uploads for any form type"""
        uploaded_files = request.FILES.getlist('images')
        image_types = request.data.get('image_types', '').split(',') if request.data.get('image_types') else []

        if not uploaded_files:
            return [], []  # No images, no errors

        # Define valid image types
        valid_image_types = [
            'passport', 'perssonal_pic', 'certificate', 'cv','masterCertificate'
            'masterCv', 'rahgeryform', 'langCertificate', 'ID_front','ID_back','university_accept',
            'form_accept','no_objection','rahgery_form','other'
        ]

        created_images = []
        errors = []

        for i, image_file in enumerate(uploaded_files):
            try:
                # Validate image
                if not application.is_valid_image(image_file):
                    errors.append(f"Invalid image format: {image_file.name}")
                    continue

                # Check file size (max 10MB)
                if image_file.size > 10 * 1024 * 1024:
                    errors.append(f"Image too large (max 10MB): {image_file.name}")
                    continue

                # Get and validate image type
                image_type = 'other'  # default
                if i < len(image_types) and image_types[i].strip():
                    requested_type = image_types[i].strip().lower()
                    if requested_type in valid_image_types:
                        image_type = requested_type
                    else:
                        errors.append(f"Invalid image type '{requested_type}' for {image_file.name}, using 'other'")

                # Generate custom path
                custom_path = self.generate_image_path(
                    application,
                    image_file.name,
                    image_type
                )

                # Save the file with custom path
                saved_path = default_storage.save(custom_path, image_file)

                # Create ApplicationImage record
                app_image = ApplicationImage.objects.create(
                    form=application,
                    image=saved_path,
                    image_type=image_type
                )
                created_images.append(app_image)

                print(f"Image saved to: {saved_path}")

            except Exception as e:
                error_msg = f"Error processing {image_file.name}: {str(e)}"
                errors.append(error_msg)
                print(f"Upload error: {error_msg}")

        return created_images, errors

    def get_serializer_class(self):
        """Use different serializer for partial updates"""
        if self.action == 'partial_update':
            return ApplicationFormPartialSerializer
        return self.serializer_class

    def partial_update(self, request, *args, **kwargs):
        """Handle PATCH requests for partial updates"""
        instance = self.get_object()

        # Check if the form is editable
        if not instance.is_editable:
            return Response(
                {"error": "This application form can no longer be edited."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Use partial=True to enable partial updates
        serializer = self.get_serializer(
            instance,
            data=request.data,
            partial=True
        )

        if serializer.is_valid():
            self.perform_update(serializer)
            return Response(serializer.data)

        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

    def perform_update(self, serializer):
        """Custom update logic"""
        serializer.save()

        # Optional: Add logging or additional business logic
        instance = serializer.instance
        print(f"ApplicationForm {instance.id} updated by user {instance.user.id}")

    # APPLICANT ENDPOINTS - Updated with filters and statistics
    @swagger_auto_schema(
        method='post',
        request_body=ApplicantFormSerializer,
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types(passport,perssonal_pic,certificate,cv,masterCertificate,masterCv,rahgeryform,langCertificate,ID_front,ID_back,university_accept,form_accept,no_objection,rahgery_form,other)",
                              type=openapi.TYPE_STRING, required=False),
        ],
        responses={201: ApplicantFormSerializer, 400: 'Bad Request'},
        operation_description="Create a new Applicant form with optional images",
        tags=['Applicant Forms']
    )
    @action(detail=False, methods=['post'], url_path='applicant')
    def create_applicant(self, request):
        """Create Applicant Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.APPLICANT, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.APPLICANT}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = ApplicantFormSerializer(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Applicant form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: ApplicantFormSerializer(many=True)},
        operation_description="List all Applicant forms with filters and search",
        tags=['Applicant Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('touch', openapi.IN_QUERY, description="Filter by touch status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('approved', openapi.IN_QUERY, description="Filter by approved status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
              openapi.Parameter('accepted', openapi.IN_QUERY, description="Filter by accepted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),

            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, phone, email",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='applicant/get')
    def list_applicant(self, request):
        """List Applicant Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.APPLICANT, ApplicantFormSerializer,
                                             search_fields=['full_name', 'phone', 'email'],
                                             filter_fields=['touch', 'submitted', 'approved', 'accepted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Applicant forms statistics",
        tags=['Applicant Forms'],
    )
    @action(detail=False, methods=['get'], url_path='applicant/stats')
    def applicant_stats(self, request):
        """Get Applicant forms statistics"""
        return self._get_form_stats(request, FormKind.APPLICANT)

    # CANCEL CODE ENDPOINTS - Updated with filters and statistics
    @swagger_auto_schema(
        method='post',
        request_body=CancelCodeFormSerializer,
        manual_parameters=[
            openapi.Parameter(
                'images',
                openapi.IN_FORM,
                description="Multiple image files (JPEG, PNG, GIF, etc.)",
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_FILE),
                required=False,
                collection_format='multi'
            ),
            openapi.Parameter(
                'image_types',
                openapi.IN_FORM,
                description="Comma-separated image types corresponding to uploaded images ('passport', 'perssonal_pic', 'certificate', 'cv','masterCertificate','masterCv', 'rahgeryform', 'langCertificate', 'ID_front','ID_back','university_accept','form_accept','no_objection','rahgery_form')",
                type=openapi.TYPE_STRING,
                required=False,
                example="before,after,damage"
            ),
        ],
        consumes=['multipart/form-data'],
        responses={201: CancelCodeFormSerializer, 400: 'Bad Request'},
        operation_description="Create a new Cancel Code form",
        tags=['Cancel Code Forms'],
    )
    @action(detail=False, methods=['post'], url_path='cancelcode')
    def create_cancelcode(self, request):
        """Create Cancel Code Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.CANCEL_CODE, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.CANCEL_CODE}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = CancelCodeFormSerializer(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Cancel Code form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: CancelCodeFormSerializer(many=True)},
        operation_description="List all Cancel Code forms with filters and search",
        tags=['Cancel Code Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, phone, email",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='cancelcode/get')
    def list_cancelcode(self, request):
        """List Cancel Code Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.CANCEL_CODE, CancelCodeFormSerializer,
                                             search_fields=['full_name', 'phone', 'email'],
                                             filter_fields=['touch', 'submitted', 'approved'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Cancel Code forms statistics",
        tags=['Cancel Code Forms'],
    )
    @action(detail=False, methods=['get'], url_path='cancelcode/stats')
    def cancelcode_stats(self, request):
        """Get Cancel Code forms statistics"""
        return self._get_form_stats(request, FormKind.CANCEL_CODE)

    # TRANSLATE ENDPOINTS - Updated with filters and statistics
    @swagger_auto_schema(
        method='post',
        request_body=TranslateFormSerializer,
        responses={201: TranslateFormSerializer, 400: 'Bad Request'},
        operation_description="Create a new Translation form",
        tags=['Translation Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='translate')
    def create_translate(self, request):
        """Create Translation Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.TRANSLATE, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.TRANSLATE}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = TranslateFormSerializer(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Translation form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: TranslateFormSerializer(many=True)},
        operation_description="List all Translation forms with filters and search",
        tags=['Translation Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, phone, email",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='translate/get')
    def list_translate(self, request):
        """List Translation Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.TRANSLATE, TranslateFormSerializer,
                                             search_fields=['full_name', 'phone', 'email'],
                                             filter_fields=['touch', 'received', 'submitted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Translation forms statistics",
        tags=['Translation Forms'],
    )
    @action(detail=False, methods=['get'], url_path='translate/stats')
    def translate_stats(self, request):
        """Get Translation forms statistics"""
        return self._get_form_stats(request, FormKind.TRANSLATE)

    # LANGUAGE COURSE ENDPOINTS - Updated with filters and statistics
    @swagger_auto_schema(
        method='post',
        request_body=LangCourseFormSerializer,
        responses={201: LangCourseFormSerializer, 400: 'Bad Request'},
        operation_description="Create a new Language Course form",
        tags=['Language Course Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='langcourse')
    def create_langcourse(self, request):
        """Create Language Course Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.LANGUAGE_COURSE, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.LANGUAGE_COURSE}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = LangCourseFormSerializer(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Language Course form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: LangCourseFormSerializer(many=True)},
        operation_description="List all Language Course forms with filters and search",
        tags=['Language Course Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, phone, email",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='langcourse/get')
    def list_langcourse(self, request):
        """List Language Course Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.LANGUAGE_COURSE, LangCourseFormSerializer,
                                             search_fields=['full_name', 'phone', 'email'],
                                             filter_fields=[ 'touch', 'submitted', 'accepted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Language Course forms statistics",
        tags=['Language Course Forms'],
    )
    @action(detail=False, methods=['get'], url_path='langcourse/stats')
    def langcourse_stats(self, request):
        """Get Language Course forms statistics"""
        return self._get_form_stats(request, FormKind.LANGUAGE_COURSE)

    # UNIVERSITY FEES ENDPOINTS - Updated with filters and statistics
    @swagger_auto_schema(
        method='post',
        request_body=UniversityFeesFormSerializer,
        responses={201: UniversityFeesFormSerializer, 400: 'Bad Request'},
        operation_description="Create a new University Fees form",
        tags=['University Fees Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='universityfees')
    def create_universityfees(self, request):
        """Create University Fees Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.UNIVERSITY_FEES, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.UNIVERSITY_FEES}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = UniversityFeesFormSerializer(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'University Fees form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: UniversityFeesFormSerializer(many=True)},
        operation_description="List all University Fees forms with filters and search",
        tags=['University Fees Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('university', openapi.IN_QUERY, description="Filter by university",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('department', openapi.IN_QUERY, description="Filter by department",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY,
                              description="Search in full_name, phone, email, university, department",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='universityfees/get')
    def list_universityfees(self, request):
        """List University Fees Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.UNIVERSITY_FEES, UniversityFeesFormSerializer,
                                             search_fields=['full_name', 'phone', 'email', 'university', 'department'],
                                             filter_fields=['touch', 'payoff', 'submitted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get University Fees forms statistics",
        tags=['University Fees Forms'],
    )
    @action(detail=False, methods=['get'], url_path='universityfees/stats')
    def universityfees_stats(self, request):
        """Get University Fees forms statistics"""
        return self._get_form_stats(request, FormKind.UNIVERSITY_FEES)

    # PUBLISH RESEARCH ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=PublishFormSerializer,
        responses={201: PublishFormSerializer, 400: 'Bad Request'},
        operation_description="Create a new Publish Research form",
        tags=['Publish Research Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='publish')
    def create_publish(self, request):
        """Create Publish Research Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.PUBLISH_RESEARCH, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.PUBLISH_RESEARCH}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = PublishFormSerializer(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Publish Research form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: PublishFormSerializer(many=True)},
        operation_description="List all Publish Research forms for the authenticated user with pagination",
        tags=['Publish Research Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('govern', openapi.IN_QUERY, description="Filter by govern", type=openapi.TYPE_STRING),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, phone, passport",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='publish/get')
    def list_publish(self, request):
        """List Publish Research Application Forms"""
        return self._list_forms_with_filters(request, FormKind.PUBLISH_RESEARCH, PublishFormSerializer,
                                             search_fields=['full_name', 'email', 'phone'],
                                             filter_fields=['touch', 'payoff', 'submitted'])


    # FLIGHT ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=Flight,
        responses={201: Flight, 400: 'Bad Request'},
        operation_description="Create a new Flight form",
        tags=['Flight Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='flight')
    def create_flight(self, request):
        """Create Flight Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.FLIGHT, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.FLIGHT}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = Flight(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Flight form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: Flight(many=True)},
        operation_description="List all Flight forms with filters and search",
        tags=['Flight Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('govern', openapi.IN_QUERY, description="Filter by govern", type=openapi.TYPE_STRING),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, phone, passport",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='flight/get')
    def list_flight(self, request):
        """List Flight Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.FLIGHT, Flight,
                                             search_fields=['full_name', 'phone', 'passport'],
                                             filter_fields=['touch', 'payoff', 'submitted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Flight forms statistics",
        tags=['Flight Forms'],
    )
    @action(detail=False, methods=['get'], url_path='flight/stats')
    def flight_stats(self, request):
        """Get Flight forms statistics"""
        return self._get_form_stats(request, FormKind.FLIGHT)

    # HIGHER EDUCATION ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=HigherEducationFile,
        responses={201: HigherEducationFile, 400: 'Bad Request'},
        operation_description="Create a new Higher Education form",
        tags=['Higher Education Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='higher-education')
    def create_higher_education(self, request):
        """Create Higher Education Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.HIGHER_EDUCATION, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.HIGHER_EDUCATION}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = HigherEducationFile(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Higher Education form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: HigherEducationFile(many=True)},
        operation_description="List all Higher Education forms with filters and search",
        tags=['Higher Education Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, email, phone",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='higher-education/get')
    def list_higher_education(self, request):
        """List Higher Education Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.HIGHER_EDUCATION, HigherEducationFile,
                                             search_fields=['full_name', 'email', 'phone'],
                                             filter_fields=['touch', 'payoff'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Higher Education forms statistics",
        tags=['Higher Education Forms'],
    )
    @action(detail=False, methods=['get'], url_path='higher-education/stats')
    def higher_education_stats(self, request):
        """Get Higher Education forms statistics"""
        return self._get_form_stats(request, FormKind.HIGHER_EDUCATION)

    # RAHGERY ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=Rahgery,
        responses={201: Rahgery, 400: 'Bad Request'},
        operation_description="Create a new Rahgery form",
        tags=['Rahgery Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='rahgery')
    def create_rahgery(self, request):
        """Create Rahgery Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.RAHGERY, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.RAHGERY}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = Rahgery(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Rahgery form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: Rahgery(many=True)},
        operation_description="List all Rahgery forms with filters and search",
        tags=['Rahgery Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('university', openapi.IN_QUERY, description="Filter by university",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('department', openapi.IN_QUERY, description="Filter by department",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY,
                              description="Search in full_name, email, phone, passport, university, department",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='rahgery/get')
    def list_rahgery(self, request):
        """List Rahgery Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.RAHGERY, Rahgery,
                                             search_fields=['full_name', 'email', 'phone', 'passport', 'university',
                                                            'department'],
                                             filter_fields=['touch', 'payoff', 'submitted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Rahgery forms statistics",
        tags=['Rahgery Forms'],
    )
    @action(detail=False, methods=['get'], url_path='rahgery/stats')
    def rahgery_stats(self, request):
        """Get Rahgery forms statistics"""
        return self._get_form_stats(request, FormKind.RAHGERY)

    # ISTALAL ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=Istalal,
        responses={201: Istalal, 400: 'Bad Request'},
        operation_description="Create a new Istalal (Research Receipt) form",
        tags=['Istalal Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='istalal')
    def create_istalal(self, request):
        """Create Istalal (Research Receipt) Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.ISTALAL, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.ISTALAL}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = Istalal(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Istalal form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: Istalal(many=True)},
        operation_description="List all Istalal forms with filters and search",
        tags=['Istalal Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, email, phone",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='istalal/get')
    def list_istalal(self, request):
        """List Istalal Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.ISTALAL, Istalal,
                                             search_fields=['full_name', 'email', 'phone'],
                                             filter_fields=['touch', 'payoff', 'submitted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Istalal forms statistics",
        tags=['Istalal Forms'],
    )
    @action(detail=False, methods=['get'], url_path='istalal/stats')
    def istalal_stats(self, request):
        """Get Istalal forms statistics"""
        return self._get_form_stats(request, FormKind.ISTALAL)

    # DELVARY ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=Delvary,
        responses={201: Delvary, 400: 'Bad Request'},
        operation_description="Create a new Delvary (Document Delivery within Iraq) form",
        tags=['Delvary Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='delvary')
    def create_delvary(self, request):
        """Create Delvary (Document Delivery within Iraq) Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.DELVARY, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.DELVARY}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = Delvary(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'Delvary form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: Delvary(many=True)},
        operation_description="List all Delvary forms with filters and search",
        tags=['Delvary Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('govern', openapi.IN_QUERY, description="Filter by govern", type=openapi.TYPE_STRING),
            openapi.Parameter('nearestPoint', openapi.IN_QUERY, description="Filter by nearest point",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, phone, address",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='delvary/get')
    def list_delvary(self, request):
        """List Delvary Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.DELVARY, Delvary,
                                             search_fields=['full_name', 'phone', 'address'],
                                             filter_fields=['touch', 'payoff', 'submitted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get Delvary forms statistics",
        tags=['Delvary Forms'],
    )
    @action(detail=False, methods=['get'], url_path='delvary/stats')
    def delvary_stats(self, request):
        """Get Delvary forms statistics"""
        return self._get_form_stats(request, FormKind.DELVARY)

    # TRANSLATE IRAQ ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=TranslateIraq,
        responses={201: TranslateIraq, 400: 'Bad Request'},
        operation_description="Create a new TranslateIraq (Translation for Language Course and Documents within Iraq) form",
        tags=['TranslateIraq Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['post'], url_path='translate-iraq')
    def create_translate_iraq(self, request):
        """Create TranslateIraq (Translation for Language Course and Documents within Iraq) Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(name=FormKind.TRANSLATE_IRAQ, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{FormKind.TRANSLATE_IRAQ}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prepare form data
        data = request.data.copy()
        data['kind'] = form_kind.id

        # Remove image-related fields from form data
        form_data = {k: v for k, v in data.items() if k not in ['images', 'image_types']}

        with transaction.atomic():
            # Create the form
            serializer = TranslateIraq(data=form_data)
            if serializer.is_valid():
                application = serializer.save(user=request.user)

                # Handle image uploads if present
                created_images, image_errors = self.handle_image_uploads(application, request)

                # Prepare response
                response_data = {
                    'form': serializer.data,
                    'message': 'TranslateIraq form created successfully'
                }

                if created_images:
                    image_serializer = ApplicationImageSerializer(
                        created_images, many=True, context={'request': request}
                    )
                    response_data['images'] = image_serializer.data
                    response_data['images_count'] = len(created_images)
                    response_data['message'] += f' with {len(created_images)} images'

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        responses={200: TranslateIraq(many=True)},
        operation_description="List all TranslateIraq forms with filters and search",
        tags=['TranslateIraq Forms'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('submitted', openapi.IN_QUERY, description="Filter by submitted status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('payoff', openapi.IN_QUERY, description="Filter by payoff status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('govern', openapi.IN_QUERY, description="Filter by govern", type=openapi.TYPE_STRING),
            openapi.Parameter('nearestPoint', openapi.IN_QUERY, description="Filter by nearest point",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_from', openapi.IN_QUERY, description="Filter from date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_to', openapi.IN_QUERY, description="Filter to date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY, description="Search in full_name, phone, address",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY, description="Order by field (prefix with - for desc)",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='translate-iraq/get')
    def list_translate_iraq(self, request):
        """List TranslateIraq Application Forms with filters and statistics"""
        return self._list_forms_with_filters(request, FormKind.TRANSLATE_IRAQ, TranslateIraq,
                                             search_fields=['full_name', 'phone', 'address'],
                                             filter_fields=['touch', 'payoff', 'submitted'])

    @swagger_auto_schema(
        method='get',
        responses={200: 'Statistics'},
        operation_description="Get TranslateIraq forms statistics",
        tags=['TranslateIraq Forms'],
    )
    @action(detail=False, methods=['get'], url_path='translate-iraq/stats')
    def translate_iraq_stats(self, request):
        """Get TranslateIraq forms statistics"""
        return self._get_form_stats(request, FormKind.TRANSLATE_IRAQ)

    # HELPER METHODS FOR FILTERING AND STATISTICS
    def _list_forms_with_filters(self, request, form_kind_name, serializer_class, search_fields=None,
                                 filter_fields=None):
        """Generic method to list forms with filters, search, and statistics"""
        try:
            form_kind = FormKind.objects.get(name=form_kind_name, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {
            "success": False,
            "error": {
                "message": f'Form kind "{form_kind_name}" not found or inactive',
                "statusCode": status.HTTP_400_BAD_REQUEST
            }},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Base queryset
        queryset = ApplicationForm.objects.filter(
            kind=form_kind,
            user=request.user
        ).prefetch_related('images').select_related('kind', 'user')

        # Apply filters
        if filter_fields:
            for field in filter_fields:
                value = request.query_params.get(field)
                if value is not None:
                    if field in ['submitted', 'payoff','touch', 'approved', 'accepted']:
                        # Boolean filters
                        queryset = queryset.filter(**{field: value.lower() == 'true'})
                    else:
                        # String filters
                        queryset = queryset.filter(**{f'{field}__icontains': value})

        # Date range filters
        date_from = request.query_params.get('date_from')
        date_to = request.query_params.get('date_to')

        if date_from:
            try:
                from datetime import datetime
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
                queryset = queryset.filter(created_at__date__gte=date_from_obj)
            except ValueError:
                pass

        if date_to:
            try:
                from datetime import datetime
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
                queryset = queryset.filter(created_at__date__lte=date_to_obj)
            except ValueError:
                pass

        # Search functionality
        search_query = request.query_params.get('search')
        if search_query and search_fields:
            from django.db.models import Q
            search_filter = Q()
            for field in search_fields:
                search_filter |= Q(**{f'{field}__icontains': search_query})
            queryset = queryset.filter(search_filter)

        # Ordering
        ordering = request.query_params.get('ordering', '-created_at')
        if ordering:
            queryset = queryset.order_by(ordering)

        # Statistics (if requested)
        include_stats = request.query_params.get('include_stats', '').lower() == 'true'
        stats = None
        if include_stats:
            stats = self._calculate_form_stats(queryset)

        # Pagination
        from rest_framework.pagination import PageNumberPagination
        paginator = PageNumberPagination()
        paginator.page_size = int(request.query_params.get('page_size', 20))
        paginated_queryset = paginator.paginate_queryset(queryset, request)

        # Serialize data
        serializer = serializer_class(paginated_queryset, many=True, context={'request': request})

        # Prepare response
        response_data = {
            "success": True,
            "message": 'done',
            "data": serializer.data,
            'count': queryset.count(),
            'page_info': {
                'current_page': paginator.page.number if paginator.page else 1,
                'total_pages': paginator.page.paginator.num_pages if paginator.page else 1,
                'page_size': paginator.page_size,
                'has_next': paginator.page.has_next() if paginator.page else False,
                'has_previous': paginator.page.has_previous() if paginator.page else False,
            }
        }

        if stats:
            response_data['statistics'] = stats

        return Response(response_data, status=status.HTTP_200_OK)

    def _get_form_stats(self, request, form_kind_name):
        """Get comprehensive statistics for a specific form type"""
        try:
            form_kind = FormKind.objects.get(name=form_kind_name, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{form_kind_name}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Base queryset
        queryset = ApplicationForm.objects.filter(
            kind=form_kind,
            user=request.user
        )

        stats = self._calculate_form_stats(queryset)
        return Response({'statistics': stats}, status=status.HTTP_200_OK)

    def _calculate_form_stats(self, queryset):
        """Calculate comprehensive statistics for a queryset"""
        from django.db.models import Count, Q
        from django.utils import timezone
        from datetime import timedelta

        total_count = queryset.count()

        if total_count == 0:
            return {
                'total_forms': 0,
                'submitted_forms': 0,
                'paid_forms': 0,
                'pending_forms': 0,
                'recent_activity': {
                    'today': 0,
                    'this_week': 0,
                    'this_month': 0,
                },
                'status_breakdown': {
                    'submitted_and_paid': 0,
                    'submitted_not_paid': 0,
                    'not_submitted_paid': 0,
                    'not_submitted_not_paid': 0,
                }
            }

        now = timezone.now()
        today = now.date()
        week_ago = today - timedelta(days=7)
        month_ago = today - timedelta(days=30)

        # Basic counts
        submitted_count = queryset.filter(submitted=True).count()
        paid_count = queryset.filter(payoff=True).count()
        pending_count = queryset.filter(submitted=False).count()

        # Recent activity
        recent_stats = {
            'today': queryset.filter(created_at__date=today).count(),
            'this_week': queryset.filter(created_at__date__gte=week_ago).count(),
            'this_month': queryset.filter(created_at__date__gte=month_ago).count(),
        }

        # Status breakdown
        status_breakdown = {
            'submitted_and_paid': queryset.filter(submitted=True, payoff=True).count(),
            'submitted_not_paid': queryset.filter(submitted=True, payoff=False).count(),
            'not_submitted_paid': queryset.filter(submitted=False, payoff=True).count(),
            'not_submitted_not_paid': queryset.filter(submitted=False, payoff=False).count(),
        }

        # Form-specific statistics (if certain fields exist)
        additional_stats = {}

        # Check if govern field exists and get distribution
        if queryset.filter(govern__isnull=False).exists():
            govern_stats = list(queryset.values('govern').annotate(count=Count('govern')).order_by('-count'))
            additional_stats['govern_distribution'] = govern_stats[:10]  # Top 10

        # Check if university field exists and get distribution
        if queryset.filter(university__isnull=False).exists():
            university_stats = list(
                queryset.values('university').annotate(count=Count('university')).order_by('-count'))
            additional_stats['university_distribution'] = university_stats[:10]  # Top 10

        return {
            'total_forms': total_count,
            'submitted_forms': submitted_count,
            'paid_forms': paid_count,
            'pending_forms': pending_count,
            'submission_rate': round((submitted_count / total_count) * 100, 2) if total_count > 0 else 0,
            'payment_rate': round((paid_count / total_count) * 100, 2) if total_count > 0 else 0,
            'recent_activity': recent_stats,
            'status_breakdown': status_breakdown,
            **additional_stats
        }
    # UTILITY ENDPOINTS
    @swagger_auto_schema(
        method='get',
        responses={200: openapi.Response(
            description="Form configuration data",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'form_kinds': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Items(type=openapi.TYPE_OBJECT)
                    ),
                    'degree_choices': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Items(type=openapi.TYPE_STRING)
                    ),
                    'governorate_choices': openapi.Schema(
                        type=openapi.TYPE_ARRAY,
                        items=openapi.Items(type=openapi.TYPE_STRING)
                    ),
                    'required_fields': openapi.Schema(type=openapi.TYPE_OBJECT)
                }
            )
        )},
        operation_description="Get form configuration including available form types, choices and required fields",
        tags=['Utility']
    )
    @action(detail=False, methods=['get'], url_path='form-config')
    def form_config(self, request):
        """Get form configuration for frontend"""
        # Get active form kinds
        active_kinds = FormKind.get_active_kinds()
        form_kinds_data = []
        required_fields = {}

        for kind in active_kinds:
            form_kinds_data.append({
                'id': kind.id,
                'name': kind.name,
                'manager': kind.manager,
                'phone': kind.phone,
                'requires_university': kind.requires_university,
                'requires_file_upload': kind.requires_file_upload,
                'icon': kind.icon,
            })
            required_fields[kind.name] = kind.get_required_fields()

        return Response({
            'form_kinds': form_kinds_data,
            'degree_choices': ApplicationForm.DEGREE_CHOICES,
            'governorate_choices': ApplicationForm.GOVERNORATE_CHOICES,
            'required_fields': required_fields
        })

    @swagger_auto_schema(
        method='get',
        responses={200: openapi.Response(
            description="User's application statistics",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'total_applications': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'by_status': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'by_kind': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'recent_applications': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )},
        operation_description="Get statistics about user's applications",
        tags=['Utility']
    )
    @action(detail=False, methods=['get'], url_path='stats')
    def user_stats(self, request):
        """Get user application statistics"""
        user_forms = self.get_queryset()

        # Count by status
        status_counts = {
            'draft': user_forms.filter(touch=False, submitted=False).count(),
            'in_progress': user_forms.filter(touch=True, submitted=False).count(),
            'submitted': user_forms.filter(submitted=True, approved=False).count(),
            'approved': user_forms.filter(approved=True, accepted=False).count(),
            'accepted': user_forms.filter(accepted=True, received=False).count(),
            'received': user_forms.filter(received=True).count(),
        }

        # Count by kind
        kind_counts = {}
        for kind in FormKind.get_active_kinds():
            count = user_forms.filter(kind=kind).count()
            if count > 0:
                kind_counts[kind.name] = {
                    'name': kind.name,
                    'count': count
                }

        # Recent applications (last 5)
        recent_forms = user_forms.order_by('-date_applied')[:5]
        recent_data = []
        for form in recent_forms:
            recent_data.append({
                'id': str(form.id),
                'kind': form.kind.name,
                'status': form.status_display,
                'date_applied': form.date_applied,
                'completion_percentage': form.get_completion_percentage(),
            })

        return Response({
            'total_applications': user_forms.count(),
            'by_status': status_counts,
            'by_kind': kind_counts,
            'recent_applications': recent_data,
        })

    # # Enhanced filtering, searching, and ordering
    filter_backends = [
        DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter
    ]

    # Define search fields (for the built-in SearchFilter)
    search_fields = [
        'full_name',
        'email',
        'phone',
        'department',
        'university__name',
        'traker',
        'user__email'
    ]

    # Define ordering fields
    ordering_fields = [
        'date_applied',
        'full_name',
        'email',
        'submitted',
        'approved',
        'accepted',
        'received',
        'university__name',
        'kind__name'
    ]
    ordering = ['-date_applied']  # Default ordering

    def get_filterset_class(self):
        """
        Return appropriate filter class based on user permissions
        """
        if self.request.user.is_staff or self.request.user.is_superuser:
            return AdminApplicationFormFilter
        return ApplicationFormFilter

    def get_queryset(self):
        """
        Enhanced queryset with better optimization and permissions
        """
        user = self.request.user

        # Base queryset with optimizations
        queryset = ApplicationForm.objects.select_related(
            'user',
            'university',
            'university__country',
            'kind'
        ).prefetch_related(
            'user__groups'
        )

        # Permission-based filtering
        if user.is_staff or user.is_superuser:
            # Staff/admin can see all applications
            return queryset
        else:
            # Regular users can only see their own applications
            return "not super"

    def perform_create(self, serializer):
        """Enhanced create with additional validation"""
        serializer.save(user=self.request.user)

    # ============ ENHANCED FILTERING ENDPOINTS ============

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('kind_name', openapi.IN_QUERY,
                              description="Filter by form kind code (applicant, translate, etc.)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('status', openapi.IN_QUERY,
                              description="Filter by status (draft, submitted, approved, etc.)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('university', openapi.IN_QUERY,
                              description="Filter by university ID",
                              type=openapi.TYPE_INTEGER),
            openapi.Parameter('university_name', openapi.IN_QUERY,
                              description="Search in university name",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('date_applied_after', openapi.IN_QUERY,
                              description="Filter applications after date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
            openapi.Parameter('date_applied_before', openapi.IN_QUERY,
                              description="Filter applications before date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING, format=openapi.FORMAT_DATE),
            openapi.Parameter('search', openapi.IN_QUERY,
                              description="Global search across multiple fields",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('degree', openapi.IN_QUERY,
                              description="Filter by degree type",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('govern', openapi.IN_QUERY,
                              description="Filter by governorate",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('needs_attention', openapi.IN_QUERY,
                              description="Filter applications needing attention (admin only)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('ordering', openapi.IN_QUERY,
                              description="Order by: date_applied, full_name, email, submitted, approved, accepted",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('page', openapi.IN_QUERY,
                              description="Page number",
                              type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY,
                              description="Number of results per page (max 100)",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: ApplicationFormSerializer(many=True)},
        operation_description="""
            Get filtered applications with comprehensive filtering options and pagination.

            Available status values:
            - draft: Not started or saved
            - in_progress: Started but not submitted
            - submitted: Waiting for approval
            - approved: Waiting for acceptance
            - accepted: Waiting to be received
            - received: Process completed
            - incomplete: Missing required fields
            - pending_review: All submitted applications
            """,
        tags=['Application Filtering']
    )
    @action(detail=False, methods=['get'], url_path='filtered')
    def get_filtered_forms(self, request):
        """Get applications with comprehensive filtering and pagination"""
        queryset = self.filter_queryset(self.get_queryset())

        # Add pagination for large result sets
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'count': queryset.count(),
            'results': serializer.data
        })

    @swagger_auto_schema(
        method='get',
        responses={200: openapi.Response(
            description="Filter statistics and available options",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'total_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'status_counts': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'kind_counts': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'university_counts': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'available_filters': openapi.Schema(type=openapi.TYPE_OBJECT),
                }
            )
        )},
        operation_description="Get filter statistics and available filter options",
        tags=['Application Filtering']
    )
    @action(detail=False, methods=['get'], url_path='filter-stats')
    def filter_stats(self, request):
        """Get statistics about available filters"""
        queryset = self.get_queryset()

        # Count by status
        status_counts = {
            'draft': queryset.filter(touch=False, submitted=False).count(),
            'in_progress': queryset.filter(touch=True, submitted=False).count(),
            'submitted': queryset.filter(submitted=True, approved=False).count(),
            'approved': queryset.filter(approved=True, accepted=False).count(),
            'accepted': queryset.filter(accepted=True, received=False).count(),
            'received': queryset.filter(received=True).count(),
        }

        # Count by kind
        kind_counts = {}
        for kind in FormKind.objects.filter(is_active=True):
            count = queryset.filter(kind=kind).count()
            if count > 0:
                kind_counts[kind.name] = {
                    'name': kind.name,
                    'count': count
                }

        # Count by university (top 10)
        from django.db.models import Count
        university_counts = {}
        universities = queryset.values('university__name').annotate(
            count=Count('id')
        ).filter(count__gt=0).order_by('-count')[:10]

        for uni in universities:
            if uni['university__name']:
                university_counts[uni['university__name']] = uni['count']

        # Available filter options
        available_filters = {
            'status_choices': [
                {'value': 'draft', 'label': 'Draft'},
                {'value': 'in_progress', 'label': 'In Progress'},
                {'value': 'submitted', 'label': 'Submitted'},
                {'value': 'approved', 'label': 'Approved'},
                {'value': 'accepted', 'label': 'Accepted'},
                {'value': 'received', 'label': 'Received'},
                {'value': 'incomplete', 'label': 'Incomplete'},
                {'value': 'pending_review', 'label': 'Pending Review'},
            ],
            'degree_choices': [
                {'value': choice[0], 'label': choice[1]}
                for choice in ApplicationForm.DEGREE_CHOICES
            ],
            'governorate_choices': [
                {'value': choice[0], 'label': choice[1]}
                for choice in ApplicationForm.GOVERNORATE_CHOICES
            ],
            'form_kinds': [
                {'value': kind.name, 'label': kind.name, 'id': kind.id}
                for kind in FormKind.objects.filter(is_active=True)
            ]
        }

        return Response({
            'total_count': queryset.count(),
            'status_counts': status_counts,
            'kind_counts': kind_counts,
            'university_counts': university_counts,
            'available_filters': available_filters,
        })

   # ============ ADMIN-ONLY FILTERING ENDPOINTS ============

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('needs_attention', openapi.IN_QUERY,
                              description="Filter applications needing admin attention",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('created_this_month', openapi.IN_QUERY,
                              description="Filter applications created this month",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('created_today', openapi.IN_QUERY,
                              description="Filter applications created today",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('is_active_user', openapi.IN_QUERY,
                              description="Filter by user active status",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('user_email', openapi.IN_QUERY,
                              description="Filter by user email",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('page', openapi.IN_QUERY,
                              description="Page number",
                              type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY,
                              description="Number of results per page (max 100)",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: ApplicationFormSerializer(many=True)},
        operation_description="Admin-only filtering with additional options and pagination",
        tags=['Admin Filtering']
    )
    @action(detail=False, methods=['get'], url_path='admin-filtered',
            permission_classes=[IsAdminUser])
    def get_admin_filtered_forms(self, request):
        """Admin-only comprehensive filtering with pagination"""
        if not (request.user.is_staff or request.user.is_superuser):
            return Response(
                {'error': 'Admin access required'},
                status=status.HTTP_403_FORBIDDEN
            )

        queryset = self.filter_queryset(self.get_queryset())

        # Apply pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response({
            'count': queryset.count(),
            'results': serializer.data
        })

    def destroy(self, request, *args, **kwargs):
        """Override destroy method to handle image cleanup for all form types"""
        instance = self.get_object()

        with transaction.atomic():
            # Delete associated images if they exist
            if hasattr(instance, 'images'):
                for image in instance.images.all():
                    try:
                        # Delete physical file
                        if image.image and default_storage.exists(image.image.name):
                            default_storage.delete(image.image.name)
                    except Exception as e:
                        print(f"Error deleting image file: {str(e)}")

            # Delete the form instance (this will cascade delete the image records)
            instance.delete()

            return Response(
            {"success": True,
                        'message': 'Form and associated images deleted successfully',
             'status':status.HTTP_204_NO_CONTENT}
            )




# Admin Dashboard Views
class AdminDashboardView(APIView):
    """Admin dashboard with statistics"""
    permission_classes = [IsSuperUserPermission]

    @swagger_auto_schema(
        operation_description="Get admin dashboard statistics",
        responses={200: openapi.Response(
            description="Dashboard statistics",
            schema=openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'total_users': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'total_applications': openapi.Schema(type=openapi.TYPE_INTEGER),
                    'applications_by_status': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'applications_by_kind': openapi.Schema(type=openapi.TYPE_OBJECT),
                    'recent_applications': openapi.Schema(type=openapi.TYPE_STRING),
                }
            )
        )},
        tags=['Admin Dashboard']
    )
    def get(self, request):
        """Get admin dashboard data"""
        from django.db.models import Count
        from datetime import datetime, timedelta

        # Basic counts
        total_users = Users.objects.count()
        total_applications = ApplicationForm.objects.count()

        # Applications by status
        status_counts = {
            'draft': ApplicationForm.objects.filter(touch=False, submitted=False).count(),
            'in_progress': ApplicationForm.objects.filter(touch=True, submitted=False).count(),
            'submitted': ApplicationForm.objects.filter(submitted=True, approved=False).count(),
            'approved': ApplicationForm.objects.filter(approved=True, accepted=False).count(),
            'accepted': ApplicationForm.objects.filter(accepted=True, received=False).count(),
            'received': ApplicationForm.objects.filter(received=True).count(),
        }

        # Applications by kind
        kind_counts = {}
        applications_by_kind = ApplicationForm.objects.values(
            'kind__name', 'kind__manager'
        ).annotate(count=Count('id'))

        for item in applications_by_kind:
            kind_counts[item['kind__name']] = {
                'name': item['kind__manager'],
                'count': item['count']
            }

        # Recent applications (last 10)
        recent_applications = ApplicationForm.objects.select_related(
            'kind', 'user', 'university'
        ).order_by('-date_applied')[:10]

        recent_data = []
        for app in recent_applications:
            recent_data.append({
                'id': str(app.id),
                'user': getattr(app.user, 'username', 'Unknown'),
                'kind': app.kind.name,
                'university': app.university.name if app.university else None,
                'status': app.status_display,
                'date_applied': app.date_applied,
            })

        return Response({
            'total_users': total_users,
            'total_applications': total_applications,
            'applications_by_status': status_counts,
            'applications_by_kind': kind_counts,
            'recent_applications': recent_data,
        })


def custom_image_upload_path(instance, filename):
    """
    Custom upload path: news/newstitle/imagetypetimestep.extension
    """
    # Get file extension
    ext = filename.split('.')[-1]

    # Clean news title for directory name
    news_title = slugify(instance.news.title)

    # Create timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]  # microseconds to milliseconds

    # Create filename: imagetype_timestamp.extension
    new_filename = f"{instance.image_type}_{timestamp}.{ext}"

    # Return full path: news/newstitle/imagetypetimestamp.extension
    return os.path.join('news', news_title, new_filename)


from rest_framework.permissions import AllowAny


class NewsTypeViewSet(viewsets.ModelViewSet):
    """ViewSet for managing news types/categories"""
    queryset = NewsType.objects.all()
    serializer_class = NewsTypeSerializer
    permission_classes = [IsSuperUserPermission]  # Default for non-GET methods
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'description']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']

    def get_permissions(self):
        """
        Override permissions to allow unauthenticated access for GET requests
        """
        if self.request.method == 'GET':
            permission_classes = [AllowAny]
        else:
            permission_classes = [IsSuperUserPermission]

        return [permission() for permission in permission_classes]

    @swagger_auto_schema(
        method='get',
        responses={200: NewsTypeSerializer(many=True)},
        operation_description="Get all active news types",
        tags=['News Types']
    )
    @action(detail=False, methods=['get'], url_path='active')
    def active_types(self, request):
        """Get only active news types"""
        active_types = NewsType.get_active_types()
        serializer = self.get_serializer(active_types, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'count': active_types.count()
        })

    @swagger_auto_schema(
        method='get',
        responses={200: openapi.Response(description="News type statistics")},
        operation_description="Get statistics for news types",
        tags=['News Types']
    )
    @action(detail=False, methods=['get'], url_path='stats')
    def type_stats(self, request):
        """Get statistics for news types"""
        stats = []
        for news_type in NewsType.objects.all():
            stats.append({
                'id': news_type.id,
                'name': news_type.name,
                'total_news': news_type.news_articles.count(),
                'published_news': news_type.news_articles.filter(status='published').count(),
                'draft_news': news_type.news_articles.filter(status='draft').count(),
                'is_active': news_type.is_active
            })

        return Response({
            'success': True,
            'data': stats
        })

class NewsViewSet(viewsets.ModelViewSet):
    """ViewSet for managing news articles with comprehensive functionality"""
    queryset = News.objects.all().select_related('news_type').prefetch_related('images')
    serializer_class = NewsSerializer
    permission_classes = [IsSuperUserPermission]
    parser_classes = [MultiPartParser, FormParser]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['title', 'content', 'excerpt', 'news_type__name']
    ordering_fields = ['created_at', 'published_at', 'title', 'views_count', 'priority']
    ordering = ['-created_at']

    def get_permissions(self):
        """
        Override permissions to allow public access to GET requests
        """
        if self.action in ['list', 'retrieve', 'published_news', 'featured_news',
                          'news_by_type', 'increment_views', 'news_stats', 'recent_news']:
            return []  # No permissions required for these actions
        return super().get_permissions()

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return NewsCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return NewsUpdateSerializer
        return NewsSerializer

    def get_queryset(self):
        """Filter queryset based on user permissions"""
        queryset = super().get_queryset()

        # For public endpoints, only show published news
        if self.action in ['list', 'retrieve', 'published_news', 'featured_news',
                          'news_by_type', 'increment_views', 'news_stats', 'recent_news']:
            return queryset.filter(status='published')

        # Non-authenticated users can only see published news
        if not self.request.user.is_authenticated:
            return queryset.filter(status='published')

        # Staff can see all, regular users see published + their drafts if applicable
        if not (self.request.user.is_staff or self.request.user.is_superuser):
            return queryset.filter(status='published')

        return queryset

    def handle_image_uploads(self, news_instance, request):
        """Handle multiple image uploads for news with custom path"""
        uploaded_files = request.FILES.getlist('images')
        image_types = request.data.get('image_types', '').split(',') if request.data.get('image_types') else []
        image_titles = request.data.get('image_titles', '').split(',') if request.data.get('image_titles') else []
        image_captions = request.data.get('image_captions', '').split(',') if request.data.get('image_captions') else []

        if not uploaded_files:
            return [], []

        valid_image_types = ['gallery', 'inline', 'thumbnail', 'banner', 'infographic', 'other']
        created_images = []
        errors = []

        for i, image_file in enumerate(uploaded_files):
            try:
                # Validate image
                if image_file.size > 10 * 1024 * 1024:  # 10MB limit
                    errors.append(f"Image too large (max 10MB): {image_file.name}")
                    continue

                # Get image metadata
                image_type = 'gallery'  # default
                if i < len(image_types) and image_types[i].strip():
                    requested_type = image_types[i].strip().lower()
                    if requested_type in valid_image_types:
                        image_type = requested_type

                title = image_titles[i].strip() if i < len(image_titles) and image_titles[i].strip() else ''
                caption = image_captions[i].strip() if i < len(image_captions) and image_captions[i].strip() else ''

                # Create custom path for image
                ext = image_file.name.split('.')[-1] if '.' in image_file.name else 'jpg'
                news_title_slug = slugify(news_instance.title)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]
                custom_filename = f"{image_type}_{timestamp}.{ext}"
                custom_path = os.path.join('news', news_title_slug, custom_filename)

                # Create NewsImage record with custom upload path
                news_image = NewsImage.objects.create(
                    news=news_instance,
                    image=image_file,
                    image_type=image_type,
                    title=title,
                    caption=caption,
                    order=i
                )

                # Move the file to custom path if needed
                if hasattr(news_image.image, 'name') and news_image.image.name != custom_path:
                    # Save with custom path
                    news_image.image.name = custom_path
                    news_image.save(update_fields=['image'])

                created_images.append(news_image)

            except Exception as e:
                error_msg = f"Error processing {image_file.name}: {str(e)}"
                errors.append(error_msg)

        return created_images, errors

    def handle_image_deletion(self, news_instance):
        """Delete all images associated with a news article"""
        deleted_files = []
        errors = []

        try:
            images = news_instance.images.all()

            for image in images:
                try:
                    if image.image and default_storage.exists(image.image.name):
                        default_storage.delete(image.image.name)
                        deleted_files.append(image.image.name)
                    image.delete()
                except Exception as e:
                    errors.append(f"Error deleting image {image.id}: {str(e)}")

            return deleted_files, errors

        except Exception as e:
            errors.append(f"Error during image deletion: {str(e)}")
            return deleted_files, errors

    @swagger_auto_schema(
        request_body=NewsCreateSerializer,
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files",
                              type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_FILE), required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="('gallery', 'inline', 'thumbnail', 'banner', 'infographic', 'other')",
                              type=openapi.TYPE_STRING, required=False),
            openapi.Parameter('image_titles', openapi.IN_FORM, description="Comma-separated image titles",
                              type=openapi.TYPE_STRING, required=False),
            openapi.Parameter('image_captions', openapi.IN_FORM, description="Comma-separated image captions",
                              type=openapi.TYPE_STRING, required=False),
        ],
        responses={201: NewsSerializer, 400: 'Bad Request'},
        operation_description="Create news article with optional images",
        tags=['News Articles']
    )
    def create(self, request, *args, **kwargs):
        """Create news article with images"""
        # Separate form data from image data
        form_data = {k: v for k, v in request.data.items()
                     if k not in ['images', 'image_types', 'image_titles', 'image_captions']}

        with transaction.atomic():
            # Create the news article
            serializer = self.get_serializer(data=form_data)
            if serializer.is_valid():
                news_instance = serializer.save()

                # Handle image uploads
                created_images, image_errors = self.handle_image_uploads(news_instance, request)

                # Prepare response
                response_data = {
                    'success': True,
                    'message': 'News article created successfully',
                    'data': NewsSerializer(news_instance, context={'request': request}).data
                }

                if created_images:
                    response_data['images_info'] = {
                        'count': len(created_images),
                        'images': NewsImageSerializer(created_images, many=True, context={'request': request}).data
                    }

                if image_errors:
                    response_data['image_warnings'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': False,
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, *args, **kwargs):
        """Delete news article with all associated images"""
        instance = self.get_object()

        with transaction.atomic():
            # Delete associated images
            deleted_files, errors = self.handle_image_deletion(instance)

            # Delete the news article
            instance.delete()

            response_data = {
                'success': True,
                'message': 'News article and associated images deleted successfully'
            }

            if deleted_files:
                response_data['deleted_images_count'] = len(deleted_files)

            if errors:
                response_data['warnings'] = errors

            return Response(response_data, status=status.HTTP_200_OK)

    # ============ CUSTOM ENDPOINTS ============

    @swagger_auto_schema(
        method='get',
        responses={200: NewsSerializer(many=True)},
        operation_description="Get all published news articles (Public Access)",
        tags=['News Articles']
    )
    @action(detail=False, methods=['get'], url_path='published')
    def published_news(self, request):
        """Get all published news - Public access"""
        published = News.get_published().select_related('news_type').prefetch_related('images')

        # Apply search and ordering only (no custom filters)
        filtered_queryset = self.filter_queryset(published)
        page = self.paginate_queryset(filtered_queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(filtered_queryset, many=True)
        return Response({
            'success': True,
            'count': filtered_queryset.count(),
            'data': serializer.data
        })

    @swagger_auto_schema(
        method='get',
        responses={200: NewsSerializer(many=True)},
        operation_description="Get featured news articles (Public Access)",
        tags=['News Articles']
    )
    @action(detail=False, methods=['get'], url_path='featured')
    def featured_news(self, request):
        """Get featured news - Public access"""
        featured = News.get_featured().select_related('news_type').prefetch_related('images')[:10]
        serializer = self.get_serializer(featured, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'count': len(featured)
        })

    @swagger_auto_schema(
        method='get',
        responses={200: NewsSerializer(many=True)},
        operation_description="List all news articles with comprehensive filters, search and pagination",
        tags=['News Articles'],
        manual_parameters=[
            # Pagination
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),

            # Filters
            openapi.Parameter('status', openapi.IN_QUERY, description="Filter by status (published/draft/archived)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('news_type', openapi.IN_QUERY, description="Filter by news type ID",
                              type=openapi.TYPE_INTEGER),
            openapi.Parameter('news_type_name', openapi.IN_QUERY, description="Filter by news type name",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('is_featured', openapi.IN_QUERY, description="Filter by featured status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('is_breaking', openapi.IN_QUERY,
                              description="Filter by breaking news status (true/false)",
                              type=openapi.TYPE_BOOLEAN),
            openapi.Parameter('priority', openapi.IN_QUERY, description="Filter by priority level",
                              type=openapi.TYPE_INTEGER),
            openapi.Parameter('min_views', openapi.IN_QUERY, description="Filter by minimum view count",
                              type=openapi.TYPE_INTEGER),
            openapi.Parameter('max_views', openapi.IN_QUERY, description="Filter by maximum view count",
                              type=openapi.TYPE_INTEGER),

            # Date Filters
            openapi.Parameter('created_from', openapi.IN_QUERY, description="Filter from creation date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('created_to', openapi.IN_QUERY, description="Filter to creation date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('published_from', openapi.IN_QUERY, description="Filter from published date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),
            openapi.Parameter('published_to', openapi.IN_QUERY, description="Filter to published date (YYYY-MM-DD)",
                              type=openapi.TYPE_STRING),

            # Search
            openapi.Parameter('search', openapi.IN_QUERY,
                              description="Search in title, content, excerpt, news_type__name",
                              type=openapi.TYPE_STRING),

            # Ordering
            openapi.Parameter('ordering', openapi.IN_QUERY,
                              description="Order by field (prefix with - for desc). Options: created_at, published_at, title, views_count, priority",
                              type=openapi.TYPE_STRING),

            # Statistics
            openapi.Parameter('include_stats', openapi.IN_QUERY, description="Include statistics in response",
                              type=openapi.TYPE_BOOLEAN),
        ]
    )
    @action(detail=False, methods=['get'], url_path='userget')
    def list_news_filtered(self, request):
        """List news articles with comprehensive filters, search and pagination"""
        queryset = self.get_queryset()

        # Apply filters
        status_filter = request.query_params.get('status')
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        news_type_id = request.query_params.get('news_type')
        if news_type_id:
            try:
                queryset = queryset.filter(news_type_id=int(news_type_id))
            except ValueError:
                pass

        news_type_name = request.query_params.get('news_type_name')
        if news_type_name:
            queryset = queryset.filter(news_type__name__icontains=news_type_name)

        is_featured = request.query_params.get('is_featured')
        if is_featured is not None:
            is_featured_bool = is_featured.lower() in ('true', '1')
            queryset = queryset.filter(is_featured=is_featured_bool)

        is_breaking = request.query_params.get('is_breaking')
        if is_breaking is not None:
            is_breaking_bool = is_breaking.lower() in ('true', '1')
            queryset = queryset.filter(is_breaking=is_breaking_bool)

        priority = request.query_params.get('priority')
        if priority:
            try:
                queryset = queryset.filter(priority=int(priority))
            except ValueError:
                pass

        min_views = request.query_params.get('min_views')
        if min_views:
            try:
                queryset = queryset.filter(views_count__gte=int(min_views))
            except ValueError:
                pass

        max_views = request.query_params.get('max_views')
        if max_views:
            try:
                queryset = queryset.filter(views_count__lte=int(max_views))
            except ValueError:
                pass

        # Date filters
        created_from = request.query_params.get('created_from')
        if created_from:
            queryset = queryset.filter(created_at__gte=created_from)

        created_to = request.query_params.get('created_to')
        if created_to:
            queryset = queryset.filter(created_at__lte=created_to + ' 23:59:59')

        published_from = request.query_params.get('published_from')
        if published_from:
            queryset = queryset.filter(published_at__gte=published_from)

        published_to = request.query_params.get('published_to')
        if published_to:
            queryset = queryset.filter(published_at__lte=published_to + ' 23:59:59')

        # Apply search
        search = request.query_params.get('search')
        if search:
            queryset = queryset.filter(
                Q(title__icontains=search) |
                Q(content__icontains=search) |
                Q(excerpt__icontains=search) |
                Q(news_type__name__icontains=search)
            )

        # Apply ordering
        ordering = request.query_params.get('ordering', '-created_at')
        # Validate ordering field
        valid_ordering_fields = ['created_at', '-created_at', 'published_at', '-published_at',
                                 'title', '-title', 'views_count', '-views_count', 'priority', '-priority']
        if ordering in valid_ordering_fields:
            queryset = queryset.order_by(ordering)
        else:
            queryset = queryset.order_by('-created_at')

        # Get statistics before pagination if requested
        include_stats = request.query_params.get('include_stats', '').lower() in ('true', '1')
        statistics = None
        if include_stats:
            statistics = self._get_filtered_statistics(queryset)

        # Pagination
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            result = self.get_paginated_response(serializer.data)

            if statistics:
                result.data['statistics'] = statistics

            return result

        # Non-paginated response
        serializer = self.get_serializer(queryset, many=True)
        response_data = {
            'success': True,
            'data': serializer.data,
            'count': queryset.count()
        }

        if statistics:
            response_data['statistics'] = statistics

        return Response(response_data)

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('type_id', openapi.IN_QUERY, description="News type ID", type=openapi.TYPE_INTEGER),
            openapi.Parameter('limit', openapi.IN_QUERY, description="Number of articles to return",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: NewsSerializer(many=True)},
        operation_description="Get news by type (Public Access)",
        tags=['News Articles']
    )
    @action(detail=False, methods=['get'], url_path='by-type')
    def news_by_type(self, request):
        """Get news filtered by type - Public access"""
        type_id = request.query_params.get('type_id')
        limit = int(request.query_params.get('limit', 20))

        if not type_id:
            return Response({
                'success': False,
                'error': 'type_id parameter is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            news_type = NewsType.objects.get(id=type_id, is_active=True)
            news_articles = news_type.news_articles.filter(status='published')[:limit]

            serializer = self.get_serializer(news_articles, many=True)
            return Response({
                'success': True,
                'type': NewsTypeSerializer(news_type).data,
                'data': serializer.data,
                'count': len(news_articles)
            })

        except NewsType.DoesNotExist:
            return Response({
                'success': False,
                'error': 'News type not found or inactive'
            }, status=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(
        method='post',
        responses={200: 'Success'},
        operation_description="Increment view count for news article (Public Access)",
        tags=['News Articles']
    )
    @action(detail=True, methods=['post'], url_path='view')
    def increment_views(self, request, pk=None):
        """Increment view count - Public access"""
        news_article = self.get_object()
        news_article.views_count += 1
        news_article.save(update_fields=['views_count'])

        return Response({
            'success': True,
            'views_count': news_article.views_count
        })

    @swagger_auto_schema(
        method='get',
        responses={200: openapi.Response(description="News statistics")},
        operation_description="Get comprehensive news statistics (Public Access)",
        tags=['News Articles']
    )
    @action(detail=False, methods=['get'], url_path='stats')
    def news_stats(self, request):
        """Get news statistics - Public access"""
        from django.db.models import Count, Sum, Avg

        now = timezone.now()
        last_week = now - timedelta(days=7)
        last_month = now - timedelta(days=30)

        # Only count published news for public stats
        total_news = News.objects.filter(status='published').count()
        featured_news = News.objects.filter(is_featured=True, status='published').count()

        # Recent activity
        recent_stats = {
            'this_week': News.objects.filter(created_at__gte=last_week, status='published').count(),
            'this_month': News.objects.filter(created_at__gte=last_month, status='published').count(),
        }

        # Popular news (top 5 by views)
        popular_news = News.objects.filter(status='published').order_by('-views_count')[:5]
        popular_serializer = NewsSerializer(popular_news, many=True, context={'request': request})

        # News by type (only published)
        type_stats = list(
            NewsType.objects.annotate(
                published_count=Count('news_articles', filter=models.Q(news_articles__status='published'))
            ).values('id', 'name', 'published_count').filter(published_count__gt=0)
        )

        return Response({
            'success': True,
            'data': {
                'totals': {
                    'published_news': total_news,
                    'featured_news': featured_news,
                },
                'recent_activity': recent_stats,
                'popular_news': popular_serializer.data,
                'by_type': type_stats,
                'total_views': News.objects.filter(status='published').aggregate(Sum('views_count'))['views_count__sum'] or 0,
                'avg_views': News.objects.filter(status='published').aggregate(Avg('views_count'))['views_count__avg'] or 0,
            }
        })

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('days', openapi.IN_QUERY, description="Number of days to look back",
                              type=openapi.TYPE_INTEGER, default=7),
        ],
        responses={200: NewsSerializer(many=True)},
        operation_description="Get recent news articles (Public Access)",
        tags=['News Articles']
    )
    @action(detail=False, methods=['get'], url_path='recent')
    def recent_news(self, request):
        """Get recent news - Public access"""
        days = int(request.query_params.get('days', 7))
        since_date = timezone.now() - timedelta(days=days)

        recent = News.objects.filter(
            status='published',
            published_at__gte=since_date
        ).select_related('news_type').prefetch_related('images')[:20]

        serializer = self.get_serializer(recent, many=True)
        return Response({
            'success': True,
            'data': serializer.data,
            'count': len(recent),
            'period': f'Last {days} days'
        })

class NewsImageViewSet(viewsets.ModelViewSet):
    """ViewSet for managing news images separately"""
    queryset = NewsImage.objects.all()
    serializer_class = NewsImageSerializer
    permission_classes = [IsSuperUserPermission]
    parser_classes = [MultiPartParser, FormParser]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['news', 'image_type', 'is_active']
    ordering_fields = ['order', 'uploaded_at']
    ordering = ['order', 'uploaded_at']

    def get_queryset(self):
        """Filter images based on permissions"""
        queryset = super().get_queryset()

        # Filter by news article if provided
        news_id = self.request.query_params.get('news_id')
        if news_id:
            queryset = queryset.filter(news_id=news_id)

        return queryset

    def destroy(self, request, *args, **kwargs):
        """Delete image with file cleanup"""
        instance = self.get_object()

        try:
            # Delete physical file
            if instance.image and default_storage.exists(instance.image.name):
                default_storage.delete(instance.image.name)

            # Delete database record
            instance.delete()

            return Response({
                'success': True,
                'message': 'Image deleted successfully'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'success': False,
                'error': f'Error deleting image: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        method='post',
        manual_parameters=[
            openapi.Parameter(
                'image_ids',
                openapi.IN_FORM,
                description="Comma-separated list of image IDs to delete",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description="Success",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'deleted_count': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'errors': openapi.Schema(type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING))
                    }
                )
            ),
            400: 'Bad Request'
        },
        operation_description="Bulk delete images by providing comma-separated image IDs",
        tags=['News Images']
    )
    @action(detail=False, methods=['post'], url_path='bulk-delete')
    def bulk_delete(self, request):
        """Bulk delete images"""
        # Handle both JSON and form data
        if hasattr(request.data, 'get'):
            # Form data or JSON
            image_ids_input = request.data.get('image_ids', [])
        else:
            # Fallback
            image_ids_input = []

        # Handle different input formats
        if isinstance(image_ids_input, str):
            # Comma-separated string
            try:
                image_ids = [int(id.strip()) for id in image_ids_input.split(',') if id.strip()]
            except ValueError:
                return Response({
                    'success': False,
                    'error': 'Invalid image IDs format. Use comma-separated integers.'
                }, status=status.HTTP_400_BAD_REQUEST)
        elif isinstance(image_ids_input, list):
            # Array of IDs
            image_ids = image_ids_input
        else:
            image_ids = []

        if not image_ids:
            return Response({
                'success': False,
                'error': 'image_ids parameter is required'
            }, status=status.HTTP_400_BAD_REQUEST)

        deleted_count = 0
        errors = []

        with transaction.atomic():
            for image_id in image_ids:
                try:
                    image = NewsImage.objects.get(id=image_id)

                    # Delete physical file
                    if image.image and default_storage.exists(image.image.name):
                        default_storage.delete(image.image.name)

                    image.delete()
                    deleted_count += 1

                except NewsImage.DoesNotExist:
                    errors.append(f'Image {image_id} not found')
                except Exception as e:
                    errors.append(f'Error deleting image {image_id}: {str(e)}')

        return Response({
            'success': True,
            'message': f'Successfully deleted {deleted_count} images',
            'deleted_count': deleted_count,
            'errors': errors if errors else None
        })