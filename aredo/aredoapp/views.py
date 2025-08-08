# Create your views here.
from datetime import datetime
from django.utils.text import slugify
from django.core.files.storage import default_storage
from django.db import transaction

from django_filters.rest_framework import DjangoFilterBackend
from .filters import *
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import filters

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
from django.core.paginator import Paginator
from django.core.files.uploadedfile import InMemoryUploadedFile
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


class CountryListCreateView(generics.ListCreateAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer
    permission_classes = [IsAdminUser]  # only admin can access
    pagination_class = CustomPageNumberPagination


class CountryRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer
    permission_classes = [IsAdminUser]


class UniversityViewSet(viewsets.ModelViewSet):
    queryset = University.objects.all()
    serializer_class = UniversitySerializer
    pagination_class = CustomPageNumberPagination

    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.AllowAny()]  # Anyone can view
        return [permissions.IsAdminUser()]  # Only admin can add/delete/edit


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


# Form Kind Management Views
class FormKindViewSet(viewsets.ModelViewSet):
    """CRUD operations for Form Kinds - Admin only for modifications"""
    queryset = FormKind.objects.all()
    serializer_class = FormKindSerializer
    pagination_class = CustomPageNumberPagination

    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.AllowAny()]
        return [IsAdminUser()]

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
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(active_kinds, many=True)
        return Response({
            'count': active_kinds.count(),
            'results': serializer.data
        })


class ApplicantViewSet(viewsets.ModelViewSet):
    queryset = ApplicationForm.objects.all()
    serializer_class = ApplicationFormSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

        # Helper methods to reduce code duplication

    def _create_form_by_code(self, request, kind_code, serializer_class):
        """Helper method to create forms of specific type using FormKind code"""
        try:
            form_kind = FormKind.objects.get(code=kind_code, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{kind_code}" not found or inactive'},
                status=status.HTTP_400_BAD_REQUEST
            )

        data = request.data.copy()
        data['kind'] = form_kind.id  # Use FormKind ID instead of code
        serializer = serializer_class(data=data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def _list_forms_by_code(self, request, kind_code, serializer_class):
        """Helper method to list forms of specific type using FormKind code with pagination"""
        try:
            form_kind = FormKind.objects.get(code=kind_code, is_active=True)
        except FormKind.DoesNotExist:
            return Response(
                {'error': f'Form kind "{kind_code}" not found or inactive'},
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
        safe_username = slugify(application.user.username)

        # Get form kind code
        form_kind = application.kind.code if application.kind else 'unknown'

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
            'passport', 'id_card', 'certificate', 'transcript',
            'photo', 'document', 'signature', 'other'
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



    # APPLICANT ENDPOINTS - Modified to handle images
    @swagger_auto_schema(
        method='post',
        request_body=ApplicantFormSerializer,
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
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
            form_kind = FormKind.objects.get(code=FormKind.APPLICANT, is_active=True)
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
        operation_description="List all Applicant forms for the authenticated user with pagination",
        tags=['Applicant Forms'],
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ]
    )
    @action(detail=False, methods=['get'], url_path='applicant')
    def list_applicant(self, request):
        """List Applicant Application Forms"""
        return self._list_forms_by_code(request, FormKind.APPLICANT, ApplicantFormSerializer)

    # CANCEL CODE ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=CancelCodeFormSerializer,
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
        responses={201: CancelCodeFormSerializer, 400: 'Bad Request'},
        operation_description="Create a new Cancel Code form",
        tags=['Cancel Code Forms'],
    )

    @action(detail=False, methods=['post'], url_path='cancelcode')
    def create_cancelcode(self, request):
        """Create Cancel Code Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(code=FormKind.CANCEL_CODE, is_active=True)
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

        with (transaction.atomic()):
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
        operation_description="List all Cancel Code forms for the authenticated user with pagination",
        tags=['Cancel Code Forms'],
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files", type=openapi.TYPE_FILE,
                              required=False),
            openapi.Parameter('image_types', openapi.IN_FORM, description="Comma-separated image types",
                              type=openapi.TYPE_STRING, required=False),
        ],
    )
    @action(detail=False, methods=['get'], url_path='cancelcode')
    def list_cancelcode(self, request):
        """List Cancel Code Application Forms"""
        return self._list_forms_by_code(request, FormKind.CANCEL_CODE, CancelCodeFormSerializer)

    # TRANSLATE ENDPOINTS
    @swagger_auto_schema(
        method='post',
        request_body=TranslateFormSerializer,
        responses={201: TranslateFormSerializer, 400: 'Bad Request'},
        operation_description="Create a new Translation form",
        tags=['Translation Forms'],
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ]
    )
    @action(detail=False, methods=['post'], url_path='translate')
    def create_translate(self, request):
        """Create Translation Application Form with optional images"""
        try:
            form_kind = FormKind.objects.get(code=FormKind.TRANSLATE, is_active=True)
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
        operation_description="List all Translation forms for the authenticated user with pagination",
        tags=['Translation Forms'],
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ]
    )
    @action(detail=False, methods=['get'], url_path='translate')
    def list_translate(self, request):
        """List Translation Application Forms"""
        return self._list_forms_by_code(request, FormKind.TRANSLATE, TranslateFormSerializer)

    # LANGUAGE COURSE ENDPOINTS
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
            form_kind = FormKind.objects.get(code=FormKind.LANGUAGE_COURSE, is_active=True)
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
        operation_description="List all Language Course forms for the authenticated user with pagination",
        tags=['Language Course Forms'],
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ]
    )
    @action(detail=False, methods=['get'], url_path='langcourse')
    def list_langcourse(self, request):
        """List Language Course Application Forms"""
        return self._list_forms_by_code(request, FormKind.LANGUAGE_COURSE, LangCourseFormSerializer)

    # UNIVERSITY FEES ENDPOINTS
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
            form_kind = FormKind.objects.get(code=FormKind.UNIVERSITY_FEES, is_active=True)
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
        operation_description="List all University Fees forms for the authenticated user with pagination",
        tags=['University Fees Forms'],
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ]
    )
    @action(detail=False, methods=['get'], url_path='universityfees')
    def list_universityfees(self, request):
        """List University Fees Application Forms"""
        return self._list_forms_by_code(request, FormKind.UNIVERSITY_FEES, UniversityFeesFormSerializer)

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
            form_kind = FormKind.objects.get(code=FormKind.PUBLISH_RESEARCH, is_active=True)
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
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ]
    )
    @action(detail=False, methods=['get'], url_path='publish')
    def list_publish(self, request):
        """List Publish Research Application Forms"""
        return self._list_forms_by_code(request, FormKind.PUBLISH_RESEARCH, PublishFormSerializer)

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
                'code': kind.code,
                'name': kind.name,
                'description': kind.description,
                'requires_university': kind.requires_university,
                'requires_file_upload': kind.requires_file_upload,
                'icon': kind.icon,
                'display_order': kind.display_order,
            })
            required_fields[kind.code] = kind.get_required_fields()

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
                kind_counts[kind.code] = {
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
            openapi.Parameter('kind_code', openapi.IN_QUERY,
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
                kind_counts[kind.code] = {
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
                {'value': kind.code, 'label': kind.name, 'id': kind.id}
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

    # ============ FORM-SPECIFIC FILTERED ENDPOINTS ============

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: ApplicantFormSerializer(many=True)},
        operation_description="Get filtered applicant forms with pagination",
        tags=['Applicant Forms']
    )
    @action(detail=False, methods=['get'], url_path='applicant/filtered')
    def get_filtered_applicant_forms(self, request):
        """Get filtered applicant forms with pagination"""
        try:
            applicant_kind = FormKind.objects.get(code=FormKind.APPLICANT, is_active=True)
            queryset = self.filter_queryset(self.get_queryset().filter(kind=applicant_kind))

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = ApplicantFormSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = ApplicantFormSerializer(queryset, many=True)
            return Response({
                'count': queryset.count(),
                'results': serializer.data
            })
        except FormKind.DoesNotExist:
            return Response({'error': 'Applicant form kind not found'},
                            status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: TranslateFormSerializer(many=True)},
        operation_description="Get filtered translation forms with pagination",
        tags=['Translation Forms']
    )
    @action(detail=False, methods=['get'], url_path='translate/filtered')
    def get_filtered_translate_forms(self, request):
        """Get filtered translation forms with pagination"""
        try:
            translate_kind = FormKind.objects.get(code=FormKind.TRANSLATE, is_active=True)
            queryset = self.filter_queryset(self.get_queryset().filter(kind=translate_kind))

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = TranslateFormSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = TranslateFormSerializer(queryset, many=True)
            return Response({
                'count': queryset.count(),
                'results': serializer.data
            })
        except FormKind.DoesNotExist:
            return Response({'error': 'Translate form kind not found'},
                            status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: CancelCodeFormSerializer(many=True)},
        operation_description="Get filtered cancel code forms with pagination",
        tags=['Cancel Code Forms']
    )
    @action(detail=False, methods=['get'], url_path='cancelcode/filtered')
    def get_filtered_cancelcode_forms(self, request):
        """Get filtered cancel code forms with pagination"""
        try:
            cancelcode_kind = FormKind.objects.get(code=FormKind.CANCEL_CODE, is_active=True)
            queryset = self.filter_queryset(self.get_queryset().filter(kind=cancelcode_kind))

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = CancelCodeFormSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = CancelCodeFormSerializer(queryset, many=True)
            return Response({
                'count': queryset.count(),
                'results': serializer.data
            })
        except FormKind.DoesNotExist:
            return Response({'error': 'Cancel Code form kind not found'},
                            status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: LangCourseFormSerializer(many=True)},
        operation_description="Get filtered language course forms with pagination",
        tags=['Language Course Forms']
    )
    @action(detail=False, methods=['get'], url_path='langcourse/filtered')
    def get_filtered_langcourse_forms(self, request):
        """Get filtered language course forms with pagination"""
        try:
            langcourse_kind = FormKind.objects.get(code=FormKind.LANGUAGE_COURSE, is_active=True)
            queryset = self.filter_queryset(self.get_queryset().filter(kind=langcourse_kind))

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = LangCourseFormSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = LangCourseFormSerializer(queryset, many=True)
            return Response({
                'count': queryset.count(),
                'results': serializer.data
            })
        except FormKind.DoesNotExist:
            return Response({'error': 'Language Course form kind not found'},
                            status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: UniversityFeesFormSerializer(many=True)},
        operation_description="Get filtered university fees forms with pagination",
        tags=['University Fees Forms']
    )
    @action(detail=False, methods=['get'], url_path='universityfees/filtered')
    def get_filtered_universityfees_forms(self, request):
        """Get filtered university fees forms with pagination"""
        try:
            universityfees_kind = FormKind.objects.get(code=FormKind.UNIVERSITY_FEES, is_active=True)
            queryset = self.filter_queryset(self.get_queryset().filter(kind=universityfees_kind))

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = UniversityFeesFormSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = UniversityFeesFormSerializer(queryset, many=True)
            return Response({
                'count': queryset.count(),
                'results': serializer.data
            })
        except FormKind.DoesNotExist:
            return Response({'error': 'University Fees form kind not found'},
                            status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        method='get',
        manual_parameters=[
            openapi.Parameter('page', openapi.IN_QUERY, description="Page number", type=openapi.TYPE_INTEGER),
            openapi.Parameter('page_size', openapi.IN_QUERY, description="Number of results per page",
                              type=openapi.TYPE_INTEGER),
        ],
        responses={200: PublishFormSerializer(many=True)},
        operation_description="Get filtered publish research forms with pagination",
        tags=['Publish Research Forms']
    )
    @action(detail=False, methods=['get'], url_path='publish/filtered')
    def get_filtered_publish_forms(self, request):
        """Get filtered publish research forms with pagination"""
        try:
            publish_kind = FormKind.objects.get(code=FormKind.PUBLISH_RESEARCH, is_active=True)
            queryset = self.filter_queryset(self.get_queryset().filter(kind=publish_kind))

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = PublishFormSerializer(page, many=True)
                return self.get_paginated_response(serializer.data)

            serializer = PublishFormSerializer(queryset, many=True)
            return Response({
                'count': queryset.count(),
                'results': serializer.data
            })
        except FormKind.DoesNotExist:
            return Response({'error': 'Publish Research form kind not found'},
                            status=status.HTTP_400_BAD_REQUEST)

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

    parser_classes = [MultiPartParser, FormParser]  # Add this for file uploads

    @swagger_auto_schema(
        method='post',
        manual_parameters=[
            openapi.Parameter(
                'images',
                openapi.IN_FORM,
                description="Multiple image files",
                type=openapi.TYPE_FILE,
                required=False
            ),
            openapi.Parameter(
                'image_types',
                openapi.IN_FORM,
                description="Comma-separated image types corresponding to uploaded images",
                type=openapi.TYPE_STRING,
                required=False
            ),
        ],
        responses={201: ApplicationFormWithImagesSerializer},
        operation_description="Upload images for an application form",
        tags=['Application Images']
    )
    @action(detail=True, methods=['post'], url_path='upload-images')
    def upload_images(self, request, pk=None):
        """Upload multiple images for a specific application"""
        application = self.get_object()

        # Check if user owns this application
        if application.user != request.user:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        # Get uploaded files
        uploaded_files = request.FILES.getlist('images')
        image_types = request.data.get('image_types', '').split(',')

        if not uploaded_files:
            return Response(
                {'error': 'No images provided'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate and save images
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

                # Get image type if provided
                image_type = 'other'
                if i < len(image_types) and image_types[i].strip():
                    image_type = image_types[i].strip()

                # Create ApplicationImage
                app_image = ApplicationImage.objects.create(
                    form=application,
                    image=image_file,
                    image_type=image_type
                )
                created_images.append(app_image)

            except Exception as e:
                errors.append(f"Error processing {image_file.name}: {str(e)}")

        # Prepare response
        if created_images:
            serializer = ApplicationImageSerializer(
                created_images,
                many=True,
                context={'request': request}
            )
            response_data = {
                'message': f'{len(created_images)} images uploaded successfully',
                'images': serializer.data
            }

            if errors:
                response_data['warnings'] = errors

            return Response(response_data, status=status.HTTP_201_CREATED)
        else:
            return Response(
                {'error': 'No images could be processed', 'details': errors},
                status=status.HTTP_400_BAD_REQUEST
            )

    @swagger_auto_schema(
        method='get',
        responses={200: ApplicationImageSerializer(many=True)},
        operation_description="Get all images for a specific application",
        tags=['Application Images']
    )
    @action(detail=True, methods=['get'], url_path='images')
    def get_images(self, request, pk=None):
        """Get all images for a specific application"""
        application = self.get_object()

        # Check permissions
        if not (request.user.is_staff or request.user.is_superuser or application.user == request.user):
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        images = application.images.all()
        serializer = ApplicationImageSerializer(
            images,
            many=True,
            context={'request': request}
        )

        return Response({
            'count': images.count(),
            'images': serializer.data
        })

    @swagger_auto_schema(
        method='delete',
        responses={204: 'Image deleted successfully'},
        operation_description="Delete a specific image",
        tags=['Application Images']
    )
    @action(detail=True, methods=['delete'], url_path='images/(?P<image_id>[^/.]+)')
    def delete_image(self, request, pk=None, image_id=None):
        """Delete a specific image"""
        application = self.get_object()

        # Check if user owns this application
        if application.user != request.user:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            image = application.images.get(id=image_id)
            image.delete()  # This will also delete the file
            return Response(
                {'message': 'Image deleted successfully'},
                status=status.HTTP_204_NO_CONTENT
            )
        except ApplicationImage.DoesNotExist:
            return Response(
                {'error': 'Image not found'},
                status=status.HTTP_404_NOT_FOUND
            )

    # SOLUTION 1: Using manual_parameters instead of request_body
    @swagger_auto_schema(
        method='patch',
        manual_parameters=[
            openapi.Parameter(
                'image_type',
                openapi.IN_FORM,
                description="Image type",
                type=openapi.TYPE_STRING,
                required=False
            ),
            openapi.Parameter(
                'description',
                openapi.IN_FORM,
                description="Image description",
                type=openapi.TYPE_STRING,
                required=False
            ),
        ],
        responses={200: ApplicationImageSerializer},
        operation_description="Update image metadata",
        tags=['Application Images']
    )
    @action(detail=True, methods=['patch'], url_path='images/(?P<image_id>[^/.]+)/update')
    def update_image(self, request, pk=None, image_id=None):
        """Update image metadata"""
        application = self.get_object()

        # Check if user owns this application
        if application.user != request.user:
            return Response(
                {'error': 'Permission denied'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            image = application.images.get(id=image_id)

            # Update allowed fields
            if 'image_type' in request.data:
                image.image_type = request.data['image_type']
            if 'description' in request.data:
                image.description = request.data['description']

            image.save()

            serializer = ApplicationImageSerializer(image, context={'request': request})
            return Response(serializer.data)

        except ApplicationImage.DoesNotExist:
            return Response(
                {'error': 'Image not found'},
                status=status.HTTP_404_NOT_FOUND
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
            'kind__code', 'kind__name'
        ).annotate(count=Count('id'))

        for item in applications_by_kind:
            kind_counts[item['kind__code']] = {
                'name': item['kind__name'],
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


class NewsViewSet(viewsets.ModelViewSet):
    queryset = News.objects.all()
    serializer_class = NewsSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

# class ApplicantViewSet(viewsets.ModelViewSet):
#     queryset = Applicant.objects.all()
#     serializer_class = ApplicantSerializer
#     permission_classes = [permissions.IsAuthenticated]
#
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
#
#
#
#
# class CancelCodeViewSet(viewsets.ModelViewSet):
#     queryset = CancelCode.objects.all()
#     serializer_class = CancelCodeSerializer
#     permission_classes = [permissions.IsAuthenticated]
#
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
#
# class TranslateViewSet(viewsets.ModelViewSet):
#     queryset = Translate.objects.all()
#     serializer_class = TranslateSerializer
#     permission_classes = [permissions.IsAuthenticated]
#
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
#
#
# class LangCourseViewSet(viewsets.ModelViewSet):
#     queryset = LangCourse.objects.all()
#     serializer_class = LangCourseSerializer
#     permission_classes = [permissions.IsAuthenticated]
#
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
#
#
# class UniversityFeesViewSet(viewsets.ModelViewSet):
#     queryset = Universityfees.objects.all()
#     serializer_class = UniversityFeesSerializer
#     permission_classes = [permissions.IsAuthenticated]
#
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)
#
#
# class PublishViewSet(viewsets.ModelViewSet):
#     queryset = Publish.objects.all()
#     serializer_class = PublishSerializer
#     permission_classes = [permissions.IsAuthenticated]
#
#     def perform_create(self, serializer):
#         serializer.save(user=self.request.user)