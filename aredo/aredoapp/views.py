# Create your views here.
from datetime import timedelta
from django.utils.text import slugify
from django.core.files.storage import default_storage
from django.db import transaction
from rest_framework.exceptions import NotFound, ValidationError
from django.http import Http404
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from .filters import *
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken

from rest_framework.permissions import IsAdminUser, IsAuthenticated
from django_filters import rest_framework as filters

import logging
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
from .serializers import *

from rest_framework.pagination import PageNumberPagination

from rest_framework.parsers import MultiPartParser, FormParser, JSONParser



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

class IsStaffUser(permissions.BasePermission):
    """Custom permission to check if user is staff"""
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_staff


class CountryListCreateView(CustomErrorMixin, generics.ListCreateAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer
    pagination_class = CustomPageNumberPagination

    def get_permissions(self):
        """Allow anyone to list, only staff can create"""
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.AllowAny()]
        return [IsStaffUser()]

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        custom_response = {
            "success": True,
            "message": "Countries retrieved successfully",
            "data": response.data
        }
        return Response(custom_response, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        custom_response = {
            "success": True,
            "message": "Country created successfully",
            "data": response.data
        }
        return Response(custom_response, status=response.status_code)


class CountryRetrieveUpdateDestroyView(CustomErrorMixin, generics.RetrieveUpdateDestroyAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer

    def get_permissions(self):
        """Allow anyone to retrieve, only staff can update/delete"""
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.AllowAny()]
        return [IsStaffUser()]

    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        custom_response = {
            "success": True,
            "message": "Country retrieved successfully",
            "data": response.data
        }
        return Response(custom_response, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        custom_response = {
            "success": True,
            "message": "Country updated successfully",
            "data": response.data
        }
        return Response(custom_response, status=response.status_code)

    def partial_update(self, request, *args, **kwargs):
        response = super().partial_update(request, *args, **kwargs)
        custom_response = {
            "success": True,
            "message": "Country updated successfully",
            "data": response.data
        }
        return Response(custom_response, status=response.status_code)

    def destroy(self, request, *args, **kwargs):
        super().destroy(request, *args, **kwargs)
        custom_response = {
            "success": True,
            "message": "Country deleted successfully",
            "data": None
        }
        return Response(custom_response, status=status.HTTP_200_OK)

class UniversityFilter(filters.FilterSet):
    """Filter universities by country, name, and type"""
    country_id = filters.UUIDFilter(field_name='country__id', lookup_expr='exact')
    name = filters.CharFilter(field_name='name', lookup_expr='icontains')
    university_type = filters.CharFilter(field_name='university_type', lookup_expr='exact')

    class Meta:
        model = University
        fields = ['name', 'university_type', 'country_id']


class UniversityViewSet(CustomErrorMixin, viewsets.ModelViewSet):
    queryset = University.objects.select_related('country')
    serializer_class = UniversitySerializer
    pagination_class = CustomPageNumberPagination
    parser_classes = [MultiPartParser, FormParser]
    filter_backends = [filters.DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = UniversityFilter
    search_fields = ['name', 'country__name']
    ordering_fields = ['name', 'created_at']
    ordering = ['name']
    lookup_field = 'id'
    lookup_value_regex = '[0-9a-f-]+'  # UUID regex pattern

    def get_permissions(self):
        """Allow anyone to view, only staff or admin users can create/update/delete"""
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.AllowAny()]
        return [IsStaffUser()]

    @swagger_auto_schema(
        operation_description="List universities with filtering and search",
        manual_parameters=[
            openapi.Parameter(
                'search',
                openapi.IN_QUERY,
                description="Search in university name and country name",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'name',
                openapi.IN_QUERY,
                description="Filter by university name (partial match)",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'university_type',
                openapi.IN_QUERY,
                description="Filter by university type (exact match)",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'country_id',
                openapi.IN_QUERY,
                description="Filter by country ID (UUID)",
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_UUID
            ),
            openapi.Parameter(
                'ordering',
                openapi.IN_QUERY,
                description="Order by fields: name, created_at (use - for descending)",
                type=openapi.TYPE_STRING
            ),
        ]
    )
    def list(self, request, *args, **kwargs):
        """List universities with filtering and search"""
        try:
            response = super().list(request, *args, **kwargs)
            custom_response = {
                "success": True,
                "message": "Universities retrieved successfully",
                "data": response.data
            }
            return Response(custom_response, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to retrieve universities',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Retrieve a specific university by ID"
    )
    def retrieve(self, request, *args, **kwargs):
        """Retrieve a specific university"""
        try:
            response = super().retrieve(request, *args, **kwargs)
            custom_response = {
                "success": True,
                "message": "University retrieved successfully",
                "data": response.data
            }
            return Response(custom_response, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to retrieve university',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Create a new university",
        request_body=UniversitySerializer,
        responses={
            201: openapi.Response(
                description="University created successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT),
                    }
                )
            )
        }
    )
    def create(self, request, *args, **kwargs):
        """Create a new university"""
        try:
            response = super().create(request, *args, **kwargs)
            custom_response = {
                "success": True,
                "message": "University created successfully",
                "data": response.data
            }
            return Response(custom_response, status=response.status_code)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to create university',
                'errors': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Update an entire university record",
        request_body=UniversitySerializer,
        responses={
            200: openapi.Response(
                description="University updated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT),
                    }
                )
            )
        }
    )
    def update(self, request, *args, **kwargs):
        """Update an entire university record"""
        try:
            response = super().update(request, *args, **kwargs)
            custom_response = {
                "success": True,
                "message": "University updated successfully",
                "data": response.data
            }
            return Response(custom_response, status=response.status_code)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to update university',
                'errors': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Partially update a university record",
        request_body=UniversitySerializer,
        responses={
            200: openapi.Response(
                description="University updated successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT),
                    }
                )
            )
        }
    )
    def partial_update(self, request, *args, **kwargs):
        """Partially update a university record"""
        try:
            response = super().partial_update(request, *args, **kwargs)
            custom_response = {
                "success": True,
                "message": "University updated successfully",
                "data": response.data
            }
            return Response(custom_response, status=response.status_code)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to update university',
                'errors': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Delete a university",
        responses={
            200: openapi.Response(
                description="University deleted successfully",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'success': openapi.Schema(type=openapi.TYPE_BOOLEAN),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_STRING, format='null'),
                    }
                )
            )
        }
    )
    def destroy(self, request, *args, **kwargs):
        """Delete a university"""
        try:
            super().destroy(request, *args, **kwargs)
            custom_response = {
                "success": True,
                "message": "University deleted successfully",
                "data": None
            }
            return Response(custom_response, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to delete university',
                'errors': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


# Form Kind Management Views
class FormKindViewSet(CustomErrorMixin, viewsets.ModelViewSet):
    """CRUD operations for Form Kinds - Admin only for modifications"""
    queryset = FormKind.objects.all()
    serializer_class = FormKindSerializer
    pagination_class = CustomPageNumberPagination
    parser_classes = [MultiPartParser, FormParser]


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


class ApplicantViewSet(CustomErrorMixin, viewsets.ModelViewSet):
    queryset = ApplicationForm.objects.all()
    serializer_class = ApplicationFormSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = CustomPageNumberPagination

    # Add parsers for file uploads
    parser_classes = [MultiPartParser, FormParser]

    # Add filtering, searching, and ordering
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]

    # Define filterable fields
    filterset_fields = {
        'submitted': ['exact'],
        'approved': ['exact'],
        'accepted': ['exact'],
        'received': ['exact'],
        'payoff': ['exact'],
        'touch': ['exact'],
        'kind': ['exact'],
        'kind__name': ['exact', 'icontains'],
        'university': ['exact'],
        'university__name': ['exact', 'icontains'],
        'date_applied': ['exact', 'gte', 'lte', 'year', 'month'],
        'fees': ['exact', 'gte', 'lte'],
    }

    # Define searchable fields
    search_fields = [
        'full_name',
        'email',
        'phone',
        'user__name',
        'user__phone_number',
        'department',
        'deepdepartment',
        'university__name',
        'kind__name',
        'degreenum',
        'passport'
    ]

    # Define ordering fields
    ordering_fields = [
        'date_applied',
        'full_name',
        'email',
        'fees',
        'updated_at'
    ]
    ordering = ['-date_applied']  # Default ordering



    def get_queryset(self):
        """Override to add select_related for better performance"""
        queryset = ApplicationForm.objects.select_related(
            'user', 'university', 'kind'
        ).prefetch_related('images')

        # Handle swagger schema generation (when request.user is AnonymousUser)
        if getattr(self, 'swagger_fake_view', False):
            return queryset

        # Filter by user if not admin and user is authenticated
        if (hasattr(self.request, 'user') and
                self.request.user.is_authenticated and
                not self.request.user.is_staff):
            queryset = queryset.filter(user=self.request.user)

        return queryset

    def create(self, request, *args, **kwargs):
        """Create application with enhanced validation based on form kind"""
        try:

            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid():
                with transaction.atomic():
                    application = self.perform_create_with_response(serializer)

                    # Handle image uploads if any
                    if request.FILES.getlist('images'):
                        created_images, errors = self.handle_image_uploads(application, request)
                        if errors:
                            print(f"Image upload errors for application {application.id}: {errors}")

                # Get the response serializer for complete data
                response_serializer = ApplicationFormWithImagesSerializer(
                    application, context={'request': request}
                )

                form_type = application.kind.manager if application.kind else 'Application'

                # Check if form is complete
                completion_percentage = application.get_completion_percentage()
                message = f'{form_type} application created successfully'
                if completion_percentage < 100:
                    message += f' (Completion: {completion_percentage}%)'

                return Response({
                    'success': True,
                    'message': message,
                    'data': response_serializer.data,
                    'completion_percentage': completion_percentage,
                    'missing_fields': application.get_missing_required_fields()
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': False,
                    'message': 'Validation failed. Please check the required fields.',
                    'errors': serializer.errors,
                    'field_requirements': self.get_form_kind_requirements(request.data.get('kind'))
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to create application',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def update(self, request, *args, **kwargs):
        """Handle PUT requests for full updates with enhanced validation"""
        try:
            instance = self.get_object()

            # Check if the form is editable



            serializer = self.get_serializer(instance, data=request.data)
            if serializer.is_valid():
                with transaction.atomic():
                    self.perform_update(serializer)

                    # Handle image uploads if any
                    if request.FILES.getlist('images'):
                        created_images, errors = self.handle_image_uploads(instance, request)
                        if errors:
                            print(f"Image upload errors during update: {errors}")

                # Return updated instance with images
                updated_serializer = ApplicationFormWithImagesSerializer(
                    instance, context={'request': request}
                )

                completion_percentage = instance.get_completion_percentage()
                message = 'Application updated successfully'
                if completion_percentage < 100:
                    message += f' (Completion: {completion_percentage}%)'

                return Response({
                    'success': True,
                    'message': message,
                    'data': updated_serializer.data,
                    'completion_percentage': completion_percentage,
                    'missing_fields': instance.get_missing_required_fields(),
                    'can_be_submitted': instance.can_be_submitted
                })
            else:
                return Response({
                    'success': False,
                    'message': 'Validation failed. Please check the required fields.',
                    'errors': serializer.errors,
                    'field_requirements': self.get_form_kind_requirements(instance.kind.id if instance.kind else None)
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to update application',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def partial_update(self, request, *args, **kwargs):
        """Handle PATCH requests for partial updates with file support"""
        try:
            instance = self.get_object()

            # Check if the form is editable
            if not instance.is_editable:
                return Response({
                    'success': False,
                    'message': 'This application form can no longer be edited.',
                    'errors': {'form': ['Form is not editable']}
                }, status=status.HTTP_403_FORBIDDEN)

            # For partial updates, only validate provided fields
            validation_errors = {}
            for field, value in request.data.items():
                if field in ['email', 'phone', 'fees', 'passport', 'university', 'date_applied']:
                    field_errors = self.validate_request_data({field: value}, instance)
                    if field_errors:
                        validation_errors.update(field_errors)

            file_errors = self.validate_file_uploads(request) if request.FILES.getlist('images') else []
            metadata_errors = self.validate_image_metadata(request) if request.FILES.getlist('images') else []

            all_errors = {}
            if validation_errors:
                all_errors.update(validation_errors)
            if file_errors:
                all_errors['file_errors'] = file_errors
            if metadata_errors:
                all_errors['metadata_errors'] = metadata_errors

            if all_errors:
                return Response({
                    'success': False,
                    'message': 'Validation failed. Please check the errors below.',
                    'errors': all_errors
                }, status=status.HTTP_400_BAD_REQUEST)

            # Use partial=True to enable partial updates
            serializer = self.get_serializer(
                instance,
                data=request.data,
                partial=True
            )

            if serializer.is_valid():
                with transaction.atomic():
                    self.perform_update(serializer)

                    # Handle image uploads if any
                    if request.FILES.getlist('images'):
                        created_images, errors = self.handle_image_uploads(instance, request)
                        if errors:
                            print(f"Image upload errors during update: {errors}")

                # Return updated instance with images
                updated_serializer = ApplicationFormWithImagesSerializer(
                    instance, context={'request': request}
                )
                return Response({
                    'success': True,
                    'message': 'Application updated successfully',
                    'data': updated_serializer.data
                })
            else:
                return Response({
                    'success': False,
                    'message': 'Validation failed. Please check the required fields.',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to update application',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_form_kind_requirements(self, kind_id):
        """Helper method to get field requirements for a specific form kind"""
        if not kind_id:
            return None

        try:
            form_kind = FormKind.objects.get(id=kind_id)
            return {
                'required_fields': form_kind.get_required_fields_list(),
                'optional_fields': form_kind.get_optional_fields_list(),
                'form_type': form_kind.manager
            }
        except FormKind.DoesNotExist:
            return None



    def get_serializer_class(self):
        """Use different serializer for different actions"""
        if self.action == 'partial_update':
            return ApplicationFormPartialSerializer
        elif self.action in ['list', 'retrieve']:
            return ApplicationFormWithImagesSerializer
        return self.serializer_class

    # ===== SWAGGER DOCUMENTATION =====
    @swagger_auto_schema(
        operation_description="List applications with advanced filtering, search, and pagination",
        manual_parameters=[
            # PAGINATION
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number (starts at 1)",
                type=openapi.TYPE_INTEGER,
                default=1
            ),
            openapi.Parameter(
                'page_size',
                openapi.IN_QUERY,
                description="Number of results per page (default: 10, max: 100)",
                type=openapi.TYPE_INTEGER,
                default=10
            ),

            # SEARCH
            openapi.Parameter(
                'search',
                openapi.IN_QUERY,
                description="Search in: full_name, email, phone, department, deepdepartment, university name, form kind, degree number, passport",
                type=openapi.TYPE_STRING
            ),

            # BOOLEAN FILTERS
            openapi.Parameter(
                'submitted',
                openapi.IN_QUERY,
                description="Filter by submitted status (true/false)",
                type=openapi.TYPE_BOOLEAN
            ),
            openapi.Parameter(
                'approved',
                openapi.IN_QUERY,
                description="Filter by approved status (true/false)",
                type=openapi.TYPE_BOOLEAN
            ),
            openapi.Parameter(
                'accepted',
                openapi.IN_QUERY,
                description="Filter by accepted status (true/false)",
                type=openapi.TYPE_BOOLEAN
            ),
            openapi.Parameter(
                'received',
                openapi.IN_QUERY,
                description="Filter by received status (true/false)",
                type=openapi.TYPE_BOOLEAN
            ),
            openapi.Parameter(
                'payoff',
                openapi.IN_QUERY,
                description="Filter by payoff status (true/false)",
                type=openapi.TYPE_BOOLEAN
            ),
            openapi.Parameter(
                'touch',
                openapi.IN_QUERY,
                description="Filter by touch status (true/false)",
                type=openapi.TYPE_BOOLEAN
            ),

            # FORM KIND FILTERS
            openapi.Parameter(
                'kind',
                openapi.IN_QUERY,
                description="Filter by form kind (exact ID)",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'kind__name',
                openapi.IN_QUERY,
                description="Filter by form kind name (exact or partial match)",
                type=openapi.TYPE_STRING
            ),

            # UNIVERSITY FILTERS
            openapi.Parameter(
                'university',
                openapi.IN_QUERY,
                description="Filter by university (exact ID)",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'university__name',
                openapi.IN_QUERY,
                description="Filter by university name (exact or partial match)",
                type=openapi.TYPE_STRING
            ),

            # DATE FILTERS
            openapi.Parameter(
                'date_applied',
                openapi.IN_QUERY,
                description="Filter by exact application date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_DATE
            ),
            openapi.Parameter(
                'date_applied__gte',
                openapi.IN_QUERY,
                description="Filter applications from this date onwards (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_DATE
            ),
            openapi.Parameter(
                'date_applied__lte',
                openapi.IN_QUERY,
                description="Filter applications until this date (YYYY-MM-DD)",
                type=openapi.TYPE_STRING,
                format=openapi.FORMAT_DATE
            ),
            openapi.Parameter(
                'date_applied__year',
                openapi.IN_QUERY,
                description="Filter by application year (e.g., 2024)",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'date_applied__month',
                openapi.IN_QUERY,
                description="Filter by application month (1-12)",
                type=openapi.TYPE_INTEGER
            ),

            # FEE FILTERS
            openapi.Parameter(
                'fees',
                openapi.IN_QUERY,
                description="Filter by exact fee amount",
                type=openapi.TYPE_NUMBER
            ),
            openapi.Parameter(
                'fees__gte',
                openapi.IN_QUERY,
                description="Filter by minimum fee amount",
                type=openapi.TYPE_NUMBER
            ),
            openapi.Parameter(
                'fees__lte',
                openapi.IN_QUERY,
                description="Filter by maximum fee amount",
                type=openapi.TYPE_NUMBER
            ),

            # ORDERING
            openapi.Parameter(
                'ordering',
                openapi.IN_QUERY,
                description="Order by field: date_applied, full_name, email, fees, updated_at (prefix - for descending, default: -date_applied)",
                type=openapi.TYPE_STRING
            ),
        ]
    )
    def list(self, request, *args, **kwargs):
        """
        List applications with advanced filtering, search, and pagination.

        Examples:
        - /api/applications/?page=1&page_size=20
        - /api/applications/?search=john&approved=true
        - /api/applications/?date_applied__gte=2024-01-01&date_applied__lte=2024-12-31
        - /api/applications/?fees__gte=1000&fees__lte=5000&ordering=-fees
        - /api/applications/?university__name__icontains=harvard&approved=true
        """
        try:
            queryset = self.filter_queryset(self.get_queryset())
            page = self.paginate_queryset(queryset)

            if page is not None:
                serializer = self.get_serializer(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)
                return Response({
                    'success': True,
                    'message': 'Applications retrieved successfully',
                    'data': paginated_response.data
                }, status=status.HTTP_200_OK)

            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'success': True,
                'message': 'Applications retrieved successfully',
                'data': {
                    'count': queryset.count(),
                    'results': serializer.data
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to retrieve applications',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def retrieve(self, request, *args, **kwargs):
        """Retrieve single application"""
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response({
                'success': True,
                'message': 'Application retrieved successfully',
                'data': serializer.data
            })
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to retrieve application',
                'errors': str(e)
            }, status=status.HTTP_404_NOT_FOUND)

    def destroy(self, request, *args, **kwargs):
        """Override destroy method to handle file cleanup with validation"""
        try:
            instance = self.get_object()

            # Check if application can be deleted
            if instance.submitted and not request.user.is_staff:
                return Response({
                    'success': False,
                    'message': 'Cannot delete submitted applications',
                    'errors': {'permission': ['Submitted applications cannot be deleted']}
                }, status=status.HTTP_403_FORBIDDEN)

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

                # Delete the PDF file if it exists
                if hasattr(instance, 'pdf') and instance.pdf:
                    try:
                        if default_storage.exists(instance.pdf.name):
                            default_storage.delete(instance.pdf.name)
                    except Exception as e:
                        print(f"Error deleting PDF file: {str(e)}")

                # Delete the form instance (this will cascade delete the image records)
                instance.delete()

            return Response({
                'success': True,
                'message': 'Application and associated files deleted successfully',
                'data': None
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to delete application',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def perform_create_with_response(self, serializer):
        """Save with current user and return the created instance"""
        return serializer.save(user=self.request.user)

    def perform_create(self, serializer):
        """Save with current user and handle file uploads"""
        application = serializer.save(user=self.request.user)

        # Handle image uploads if any
        if self.request.FILES.getlist('images'):
            created_images, errors = self.handle_image_uploads(application, self.request)
            if errors:
                # Log errors but don't fail the creation
                print(f"Image upload errors for application {application.id}: {errors}")

    def generate_image_path(self, application, original_filename, image_type='general'):
        """
        Generate structured path: form_kind/username/date/image_type_timestamp.ext
        Example: applicant/john_doe/2025-08-08/passport_20250808_143022.jpg
        """
        # Get file extension
        file_ext = os.path.splitext(original_filename)[1].lower()

        # Create safe username (slug format)
        safe_username = slugify(application.user.name)

        # Get form kind name
        form_kind = application.kind.name if application.kind else 'unknown'

        # Get current date
        current_date = datetime.now()
        date_str = current_date.strftime('%Y-%m-%d')
        timestamp = current_date.strftime('%Y%m%d_%H%M%S_%f')[:17]  # Include microseconds for uniqueness

        # Create structured path
        custom_path = f"application_images/{form_kind}/{safe_username}/{date_str}/{image_type}_{timestamp}{file_ext}"

        return custom_path

    def handle_image_uploads(self, application, request):
        """Helper method to handle image uploads for any form type with enhanced validation"""
        uploaded_files = request.FILES.getlist('images')
        image_types = request.data.get('image_types', '').split(',') if request.data.get('image_types') else []
        image_descriptions = request.data.get('image_descriptions', '').split(',') if request.data.get(
            'image_descriptions') else []

        if not uploaded_files:
            return [], []  # No images, no errors

        # Define valid image types
        valid_image_types = [
            'passport', 'personal_pic', 'certificate', 'cv', 'master_certificate',
            'master_cv', 'rahgery_form', 'lang_certificate', 'id_front', 'id_back',
            'university_accept', 'form_accept', 'no_objection', 'transcript', 'other'
        ]

        created_images = []
        errors = []

        # Validate total number of existing images
        existing_images_count = application.images.count() if hasattr(application, 'images') else 0
        if existing_images_count + len(uploaded_files) > 15:  # Max 15 images per application
            errors.append(
                f"Too many images. Maximum 15 images allowed per application (current: {existing_images_count})")
            return created_images, errors

        for i, image_file in enumerate(uploaded_files):
            try:
                # Validate image file type
                allowed_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.pdf']
                file_ext = os.path.splitext(image_file.name)[1].lower()

                if file_ext not in allowed_extensions:
                    errors.append(f"Invalid file type for {image_file.name}. Allowed: {', '.join(allowed_extensions)}")
                    continue

                # Check file size (max 10MB)
                if image_file.size > 10 * 1024 * 1024:
                    errors.append(f"File too large (max 10MB): {image_file.name}")
                    continue

                # Check for duplicate image types (except 'other')
                image_type = 'other'  # default
                if i < len(image_types) and image_types[i].strip():
                    requested_type = image_types[i].strip().lower()
                    if requested_type in valid_image_types:
                        image_type = requested_type

                        # Check for duplicates (except 'other' and 'certificate')
                        if image_type not in ['other', 'certificate']:
                            existing_type = application.images.filter(image_type=image_type).exists()
                            if existing_type:
                                errors.append(f"Image type '{image_type}' already exists for this application")
                                continue
                    else:
                        errors.append(f"Invalid image type '{requested_type}' for {image_file.name}, using 'other'")

                # Get description with length validation
                description = ''
                if i < len(image_descriptions) and image_descriptions[i].strip():
                    description = image_descriptions[i].strip()
                    if len(description) > 500:
                        errors.append(f"Description too long for {image_file.name} (max 500 characters)")
                        description = description[:500]

                # Validate image content if it's an image file
                if file_ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp']:
                    try:
                        from PIL import Image
                        img = Image.open(image_file)
                        img.verify()
                        image_file.seek(0)  # Reset file pointer

                        # Additional image validations
                        if img.size[0] < 100 or img.size[1] < 100:
                            errors.append(f"Image {image_file.name} too small (minimum 100x100 pixels)")
                            continue

                        if img.size[0] > 5000 or img.size[1] > 5000:
                            errors.append(f"Image {image_file.name} too large (maximum 5000x5000 pixels)")
                            continue

                    except Exception as e:
                        errors.append(f"Invalid or corrupted image: {image_file.name}")
                        continue

                # Generate custom path
                custom_path = self.generate_image_path(
                    application,
                    image_file.name,
                    image_type
                )

                # Check if file with same path exists
                if default_storage.exists(custom_path):
                    # Generate new path with additional timestamp
                    import time
                    timestamp_suffix = str(int(time.time() * 1000000))
                    name_part, ext_part = os.path.splitext(custom_path)
                    custom_path = f"{name_part}_{timestamp_suffix}{ext_part}"

                # Save the file with custom path
                saved_path = default_storage.save(custom_path, image_file)

                # Create ApplicationImage record
                app_image = ApplicationImage.objects.create(
                    form=application,
                    image=saved_path,
                    image_type=image_type,
                    description=description
                )
                created_images.append(app_image)

                print(f"File saved to: {saved_path}")

            except Exception as e:
                error_msg = f"Error processing {image_file.name}: {str(e)}"
                errors.append(error_msg)
                print(f"Upload error: {error_msg}")

        return created_images, errors

    def perform_update(self, serializer):
        """Custom update logic with validation"""
        # Store old values for comparison
        old_instance = self.get_object()
        old_status = old_instance.status if hasattr(old_instance, 'status') else None

        serializer.save()

        # Optional: Add logging or additional business logic
        instance = serializer.instance

        # Log status changes
        if hasattr(instance, 'status') and old_status != instance.status:
            print(
                f"ApplicationForm {instance.id} status changed from {old_status} to {instance.status} by user {instance.user.id}")

        print(f"ApplicationForm {instance.id} updated by user {instance.user.id}")

    # Helper methods for backward compatibility
    def _create_form_by_code(self, request, kind_name, serializer_class):
        """Helper method to create forms of specific type using FormKind name with validation"""
        try:
            form_kind = FormKind.objects.get(name=kind_name, is_active=True)
        except FormKind.DoesNotExist:
            return Response({
                'success': False,
                'message': f'Form kind "{kind_name}" not found or inactive',
                'errors': {'kind': [f'Form kind "{kind_name}" not found or inactive']}
            }, status=status.HTTP_400_BAD_REQUEST)

        data = request.data.copy()
        data['kind'] = form_kind.id  # Use FormKind ID

        # Apply enhanced validation
        validation_errors = self.validate_request_data(data)
        file_errors = self.validate_file_uploads(request)
        metadata_errors = self.validate_image_metadata(request)

        all_errors = {}
        if validation_errors:
            all_errors.update(validation_errors)
        if file_errors:
            all_errors['file_errors'] = file_errors
        if metadata_errors:
            all_errors['metadata_errors'] = metadata_errors

        if all_errors:
            return Response({
                'success': False,
                'message': 'Validation failed. Please check the errors below.',
                'errors': all_errors
            }, status=status.HTTP_400_BAD_REQUEST)

        serializer = serializer_class(data=data)
        if serializer.is_valid():
            try:
                with transaction.atomic():
                    application = serializer.save(user=request.user)

                    # Handle file uploads
                    if request.FILES.getlist('images'):
                        created_images, errors = self.handle_image_uploads(application, request)
                        if errors:
                            print(f"Image upload errors: {errors}")

                # Get response with full data
                response_serializer = ApplicationFormWithImagesSerializer(
                    application, context={'request': request}
                )

                return Response({
                    'success': True,
                    'message': f'{kind_name} application created successfully',
                    'data': response_serializer.data
                }, status=status.HTTP_201_CREATED)
            except Exception as e:
                return Response({
                    'success': False,
                    'message': 'Failed to create application',
                    'errors': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response({
                'success': False,
                'message': 'Validation failed. Please check the required fields.',
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

    def _list_forms_by_code(self, request, kind_name, serializer_class):
        """Helper method to list forms of specific type using FormKind name with pagination and validation"""
        try:
            form_kind = FormKind.objects.get(name=kind_name, is_active=True)
        except FormKind.DoesNotExist:
            return Response({
                'success': False,
                'message': f'Form kind "{kind_name}" not found or inactive',
                'errors': {'kind': [f'Form kind "{kind_name}" not found or inactive']}
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            queryset = self.get_queryset().filter(kind=form_kind)

            # Validate query parameters
            query_errors = []

            # Validate date parameters
            for date_param in ['date_applied__gte', 'date_applied__lte']:
                if date_param in request.query_params:
                    try:
                        from django.utils.dateparse import parse_date
                        date_value = parse_date(request.query_params[date_param])
                        if not date_value:
                            query_errors.append(f"Invalid date format for {date_param}. Use YYYY-MM-DD")
                    except Exception:
                        query_errors.append(f"Invalid date format for {date_param}. Use YYYY-MM-DD")

            # Validate ordering parameters
            if 'ordering' in request.query_params:
                ordering_fields = request.query_params['ordering'].split(',')
                valid_ordering_fields = [f for f in self.ordering_fields] + [f'-{f}' for f in self.ordering_fields]
                for field in ordering_fields:
                    if field.strip() not in valid_ordering_fields:
                        query_errors.append(f"Invalid ordering field: {field}")

            if query_errors:
                return Response({
                    'success': False,
                    'message': 'Invalid query parameters',
                    'errors': {'query_params': query_errors}
                }, status=status.HTTP_400_BAD_REQUEST)

            # Apply filtering and searching
            queryset = self.filter_queryset(queryset)

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = serializer_class(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)
                return Response({
                    'success': True,
                    'message': f'{kind_name} applications retrieved successfully',
                    'data': paginated_response.data
                })

            serializer = serializer_class(queryset, many=True)
            return Response({
                'success': True,
                'message': f'{kind_name} applications retrieved successfully',
                'data': {
                    'count': queryset.count(),
                    'results': serializer.data
                }
            })
        except Exception as e:
            return Response({
                'success': False,
                'message': 'Failed to retrieve applications',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Admin Dashboard Views
class AdminDashboardView(APIView):
    """Admin dashboard with statistics"""
    permission_classes = [IsStaffUser]

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


# def custom_image_upload_path(instance, filename):
#     """
#     Custom upload path: news/newstitle/imagetypetimestep.extension
#     """
#     # Get file extension
#     ext = filename.split('.')[-1]
#
#     # Clean news title for directory name
#     news_title = slugify(instance.news.title)
#
#     # Create timestamp
#     timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]  # microseconds to milliseconds
#
#     # Create filename: imagetype_timestamp.extension
#     new_filename = f"{instance.image_type}_{timestamp}.{ext}"
#
#     # Return full path: news/newstitle/imagetypetimestamp.extension
#     return os.path.join('news', news_title, new_filename)


from rest_framework.permissions import AllowAny


class NewsTypeViewSet(viewsets.ModelViewSet):
    """ViewSet for managing news types/categories"""
    queryset = NewsType.objects.all()
    serializer_class = NewsTypeSerializer
    permission_classes = [IsSuperUserPermission,IsStaffUser]  # Default for non-GET methods
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
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
            permission_classes = [IsSuperUserPermission,IsStaffUser]

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




logger = logging.getLogger(__name__)


class NewsPagePagination(PageNumberPagination):
    """Custom pagination for news articles"""
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        return Response({
            'success': True,
            'count': self.page.paginator.count,
            'total_pages': self.page.paginator.num_pages,
            'current_page': self.page.number,
            'page_size': self.get_page_size(self.request),
            'next': self.get_next_link(),
            'previous': self.get_previous_link(),
            'data': data
        })


class NewsViewSet(viewsets.ModelViewSet):
    """ViewSet for managing news articles"""
    queryset = News.objects.all().prefetch_related('images')
    serializer_class = NewsSerializer
    parser_classes = [MultiPartParser, FormParser]
    pagination_class = NewsPagePagination

    def get_permissions(self):
        """All GET actions without auth, POST/PUT/DELETE require auth"""
        if self.action in ['list', 'retrieve', 'published_news', 'recent_news']:
            return []  # No permissions required for GET actions
        return [IsAuthenticated()]  # Auth required for create/update/delete

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return NewsCreateSerializer
        return NewsSerializer

    def handle_image_uploads(self, news_instance, request):
        """Handle image uploads with original name + datetime"""
        uploaded_files = request.FILES.getlist('images')

        if not uploaded_files:
            return [], []

        created_images = []
        errors = []

        for image_file in uploaded_files:
            try:
                # Validate image size (10MB limit)
                if image_file.size > 10 * 1024 * 1024:
                    errors.append(f"Image too large (max 10MB): {image_file.name}")
                    continue

                # Create filename with original name + datetime
                original_name = os.path.splitext(image_file.name)[0]
                extension = os.path.splitext(image_file.name)[1]
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                new_filename = f"{original_name}_{timestamp}{extension}"

                # Update the file name
                image_file.name = new_filename

                # Create NewsImage record
                news_image = NewsImage.objects.create(
                    news=news_instance,
                    image=image_file
                )

                created_images.append(news_image)
                logger.info(f"Image uploaded: {new_filename}")

            except Exception as e:
                error_msg = f"Error processing {image_file.name}: {str(e)}"
                errors.append(error_msg)
                logger.error(error_msg)

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

        except Exception as e:
            errors.append(f"Error during image deletion: {str(e)}")

        return deleted_files, errors

    @swagger_auto_schema(
        request_body=NewsCreateSerializer,
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files",
                              type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_FILE),
                              required=False),
        ],
        responses={201: NewsSerializer, 400: 'Bad Request'},
        operation_description="Create news article with optional images (Auth Required)",
        tags=['News Articles']
    )
    def create(self, request, *args, **kwargs):
        """Create news article with images"""
        # Separate form data from image data
        form_data = {k: v for k, v in request.data.items() if k != 'images'}

        try:
            with transaction.atomic():
                # Create the news article
                serializer = self.get_serializer(data=form_data)
                if not serializer.is_valid():
                    return Response({
                        'success': False,
                        'errors': serializer.errors
                    }, status=status.HTTP_400_BAD_REQUEST)

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
                    response_data['images_uploaded'] = len(created_images)

                if image_errors:
                    response_data['image_errors'] = image_errors

                return Response(response_data, status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.error(f"Error creating news article: {str(e)}")
            return Response({
                'success': False,
                'error': 'An error occurred while creating the news article'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        request_body=NewsSerializer,
        manual_parameters=[
            openapi.Parameter('images', openapi.IN_FORM, description="Multiple image files",
                              type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_FILE),
                              required=False),
        ],
        responses={200: NewsSerializer, 400: 'Bad Request'},
        operation_description="Update news article with optional new images (Auth Required)",
        tags=['News Articles']
    )
    def update(self, request, *args, **kwargs):
        """Update news article with optional new images"""
        instance = self.get_object()
        form_data = {k: v for k, v in request.data.items() if k != 'images'}

        try:
            with transaction.atomic():
                # Update the news article
                serializer = self.get_serializer(instance, data=form_data, partial=True)
                if not serializer.is_valid():
                    return Response({
                        'success': False,
                        'errors': serializer.errors
                    }, status=status.HTTP_400_BAD_REQUEST)

                news_instance = serializer.save()

                # Handle new image uploads if provided
                created_images = []
                image_errors = []
                if 'images' in request.FILES:
                    created_images, image_errors = self.handle_image_uploads(news_instance, request)

                response_data = {
                    'success': True,
                    'message': 'News article updated successfully',
                    'data': NewsSerializer(news_instance, context={'request': request}).data
                }

                if created_images:
                    response_data['new_images_uploaded'] = len(created_images)

                if image_errors:
                    response_data['image_errors'] = image_errors

                return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error updating news article: {str(e)}")
            return Response({
                'success': False,
                'error': 'An error occurred while updating the news article'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def destroy(self, request, *args, **kwargs):
        """Delete news article with all associated images (Auth Required)"""
        instance = self.get_object()

        try:
            with transaction.atomic():
                # Delete associated images
                deleted_files, errors = self.handle_image_deletion(instance)

                # Store title for logging
                title = instance.title

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

                logger.info(f"News article deleted: {title}")
                return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error deleting news article: {str(e)}")
            return Response({
                'success': False,
                'error': 'An error occurred while deleting the news article'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    # ============ PUBLIC GET ENDPOINTS (No Auth Required) ============

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('news_type_id', openapi.IN_QUERY,
                              description="Filter by news type ID (UUID format)",
                              type=openapi.TYPE_STRING, required=False),
            openapi.Parameter('search', openapi.IN_QUERY,
                              description="Search in title and content",
                              type=openapi.TYPE_STRING, required=False),
            openapi.Parameter('page', openapi.IN_QUERY,
                              description="Page number",
                              type=openapi.TYPE_INTEGER, required=False),
            openapi.Parameter('page_size', openapi.IN_QUERY,
                              description="Number of results per page (max 100)",
                              type=openapi.TYPE_INTEGER, required=False),
        ],
        responses={200: NewsSerializer(many=True)},
        operation_description="Get paginated news articles with filtering options (Public Access)",
        tags=['News Articles']
    )
    def list(self, request, *args, **kwargs):
        """List all news articles with pagination and filtering (Public Access)"""
        try:
            queryset = self.get_queryset()

            # Filter by news_type_id
            news_type_id = request.query_params.get('news_type_id')
            if news_type_id:
                try:
                    # Validate UUID format
                    uuid.UUID(news_type_id)
                    queryset = queryset.filter(news_type_id=news_type_id)
                except ValueError:
                    return Response({
                        'success': False,
                        'error': 'Invalid news_type_id format. Must be a valid UUID.'
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Search functionality
            search = request.query_params.get('search')
            if search:
                queryset = queryset.filter(
                    Q(title__icontains=search) |
                    Q(content__icontains=search)
                )

            # Default ordering
            queryset = queryset.order_by('-created_at')

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)

                # Add filter information to response
                filters_applied = {}
                if news_type_id:
                    filters_applied['news_type_id'] = news_type_id
                if search:
                    filters_applied['search'] = search

                if filters_applied:
                    paginated_response.data['filters_applied'] = filters_applied

                return paginated_response

            # Fallback if pagination is disabled
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'success': True,
                'count': len(serializer.data),
                'data': serializer.data
            })

        except Exception as e:
            logger.error(f"Error fetching news list: {str(e)}")
            return Response({
                'success': False,
                'error': 'Unable to fetch news articles'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        responses={200: NewsSerializer},
        operation_description="Get single news article (Public Access)",
        tags=['News Articles']
    )
    def retrieve(self, request, *args, **kwargs):
        """Get single news article (Public Access)"""
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response({
                'success': True,
                'data': serializer.data
            })
        except Exception as e:
            logger.error(f"Error fetching news article: {str(e)}")
            return Response({
                'success': False,
                'error': 'News article not found'
            }, status=status.HTTP_404_NOT_FOUND)



    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter('news_type_id', openapi.IN_QUERY,
                              description="Filter by news type ID (UUID format)",
                              type=openapi.TYPE_STRING, required=False),
            openapi.Parameter('search', openapi.IN_QUERY,
                              description="Search in title and content",
                              type=openapi.TYPE_STRING, required=False),
            openapi.Parameter('page', openapi.IN_QUERY,
                              description="Page number",
                              type=openapi.TYPE_INTEGER, required=False),
            openapi.Parameter('page_size', openapi.IN_QUERY,
                              description="Number of results per page (max 100)",
                              type=openapi.TYPE_INTEGER, required=False),
        ],
        responses={200: NewsSerializer(many=True)},
        operation_description="GET for user",
        tags=['News Articles']
    )
    @action(detail=False, methods=['get'], url_path='userget')
    def recent_news(self, request):
        try:
            queryset = self.get_queryset()

            # Filter by news_type_id
            news_type_id = request.query_params.get('news_type_id')
            if news_type_id:
                try:
                    # Validate UUID format
                    uuid.UUID(news_type_id)
                    queryset = queryset.filter(news_type_id=news_type_id)
                except ValueError:
                    return Response({
                        'success': False,
                        'error': 'Invalid news_type_id format. Must be a valid UUID.'
                    }, status=status.HTTP_400_BAD_REQUEST)

            # Search functionality
            search = request.query_params.get('search')
            if search:
                queryset = queryset.filter(
                    Q(title__icontains=search) |
                    Q(content__icontains=search)
                )

            # Default ordering
            queryset = queryset.order_by('-created_at')

            # Apply pagination
            page = self.paginate_queryset(queryset)
            if page is not None:
                serializer = self.get_serializer(page, many=True)
                paginated_response = self.get_paginated_response(serializer.data)

                # Add filter information to response
                filters_applied = {}
                if news_type_id:
                    filters_applied['news_type_id'] = news_type_id
                if search:
                    filters_applied['search'] = search

                if filters_applied:
                    paginated_response.data['filters_applied'] = filters_applied

                return paginated_response

            # Fallback if pagination is disabled
            serializer = self.get_serializer(queryset, many=True)
            return Response({
                'success': True,
                'count': len(serializer.data),
                'data': serializer.data
            })

        except Exception as e:
            logger.error(f"Error fetching news list: {str(e)}")
            return Response({
                'success': False,
                'error': 'Unable to fetch news articles'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class NewsImageViewSet(viewsets.ModelViewSet):
    """ViewSet for managing news images separately"""
    queryset = NewsImage.objects.all()
    serializer_class = NewsImageSerializer
    permission_classes = [IsSuperUserPermission]
    parser_classes = [MultiPartParser, FormParser]
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_fields = ['news', 'is_active']
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
