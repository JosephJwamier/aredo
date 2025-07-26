from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

# DRF router for University
router = DefaultRouter()
router.register(r'universities', UniversityViewSet, basename='university')
router.register(r'applicants', ApplicantViewSet)
router.register(r'cancelcode', CancelCodeViewSet)
router.register(r'news', NewsViewSet)
router.register(r'translate', TranslateViewSet)
router.register(r'lang', LangCourseViewSet)
router.register(r'fees',UniversityFeesViewSet )
router.register(r'publish', PublishViewSet)

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', TokenObtainPairView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Country endpoints
    path('countries/', CountryListCreateView.as_view(), name='country-list-create'),
    path('countries/<int:pk>/', CountryRetrieveUpdateDestroyView.as_view(), name='country-detail'),

    # University viewset endpoints
    path('', include(router.urls)),
]
