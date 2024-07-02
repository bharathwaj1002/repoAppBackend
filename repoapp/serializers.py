from rest_framework import serializers
from .models import *


class RegisteredUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegisteredUser
        fields = '__all__'
        
        
class PullRequestSerializer(serializers.ModelSerializer):
    class Meta:
        model = PullRequest
        fields = '__all__'
        
        

        
class RepositorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Repositories
        fields = '__all__'
    
class PointSerializer(serializers.ModelSerializer):
    class Meta:
        model = Point
        fields = '__all__'