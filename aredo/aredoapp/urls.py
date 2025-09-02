from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
from rest_framework_simplejwt.views import  TokenRefreshView

# DRF router for University
router = DefaultRouter()
router.register(r'universities', UniversityViewSet, basename='university')
router.register(r'news', NewsViewSet)
router.register(r'newstype', NewsTypeViewSet)
router.register(r'news-images', NewsImageViewSet)
router.register(r'forms', ApplicantViewSet)
router.register(r'form-kinds', FormKindViewSet, basename='formkind')


urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', MyTokenObtainPairView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Country endpoints
    path('countries/', CountryListCreateView.as_view(), name='country-list-create'),
    path('countries/<uuid:pk>/', CountryRetrieveUpdateDestroyView.as_view(), name='country-detail'),

    # University viewset endpoints
    path('', include(router.urls)),

    # Admin user management endpoints
    path('admin/users/create/', AdminUserCreateView.as_view(), name='admin-user-create'),
    path('admin/users/', AdminUserListView.as_view(), name='admin-user-list'),
    path('admin/users/<uuid:id>/', AdminUserDetailView.as_view(), name='admin-user-detail'),
    path('admin/users/<uuid:id>/update/', AdminUserUpdateView.as_view(), name='admin-user-update'),
    path('admin/users/<uuid:user_id>/toggle-status/', toggle_user_status, name='admin-user-toggle-status'),
    path('api/admin/dashboard/', AdminDashboardView.as_view(), name='admin-dashboard'),
]
