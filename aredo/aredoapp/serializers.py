from rest_framework import serializers
from .models import *
from django.contrib.auth import authenticate

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['id', 'email', 'name']

class RegisterSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['email', 'name', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = Users.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            password=validated_data['password']
        )
        return user


class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Country
        fields = '__all__'


class UniversitySerializer(serializers.ModelSerializer):
    country = serializers.PrimaryKeyRelatedField(queryset=Country.objects.all())

    class Meta:
        model = University
        fields = '__all__'



class ApplicantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Applicant
        fields = '__all__'
        read_only_fields = ['user', 'date_applied', 'approved']



class CancelCodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CancelCode
        fields = '__all__'

class NewsSerializer(serializers.ModelSerializer):
    class Meta:
        model = News
        fields = '__all__'


class TranslateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Translate
        fields = '__all__'

class LangCourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = LangCourse
        fields = '__all__'


class UniversityFeesSerializer(serializers.ModelSerializer):
    class Meta:
        model = Universityfees
        fields = '__all__'


class PublishSerializer(serializers.ModelSerializer):
    class Meta:
        model = Publish
        fields = '__all__'