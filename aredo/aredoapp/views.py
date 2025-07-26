from django.shortcuts import render

# Create your views here.
from rest_framework import generics, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import viewsets
from rest_framework.permissions import IsAdminUser
from .models import Users
from .serializers import *
from rest_framework.views import APIView

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

class CountryRetrieveUpdateDestroyView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Country.objects.all()
    serializer_class = CountrySerializer
    permission_classes = [IsAdminUser]

class UniversityViewSet(viewsets.ModelViewSet):
    queryset = University.objects.all()
    serializer_class = UniversitySerializer

    def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return [permissions.AllowAny()]  # Anyone can view
        return [permissions.IsAdminUser()]  # Only admin can add/delete/edit



class ApplicantViewSet(viewsets.ModelViewSet):
    queryset = Applicant.objects.all()
    serializer_class = ApplicantSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)




class CancelCodeViewSet(viewsets.ModelViewSet):
    queryset = CancelCode.objects.all()
    serializer_class = CancelCodeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class NewsViewSet(viewsets.ModelViewSet):
    queryset = News.objects.all()
    serializer_class = NewsSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class TranslateViewSet(viewsets.ModelViewSet):
    queryset = Translate.objects.all()
    serializer_class = TranslateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class LangCourseViewSet(viewsets.ModelViewSet):
    queryset = LangCourse.objects.all()
    serializer_class = LangCourseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class UniversityFeesViewSet(viewsets.ModelViewSet):
    queryset = Universityfees.objects.all()
    serializer_class = UniversityFeesSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class PublishViewSet(viewsets.ModelViewSet):
    queryset = Publish.objects.all()
    serializer_class = PublishSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)