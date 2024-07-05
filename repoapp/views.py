import time
from django.conf import settings
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from .serializers import *
import json
import jwt
import requests
from asgiref.sync import async_to_sync
from .models import PullRequest


# Create your views here.
def pull_requests_list(request):
    pull_requests = PullRequest.objects.all()
    serializer = PullRequestSerializer(pull_requests, many=True)
    return JsonResponse(serializer.data, safe=False)

def repositories_list(request):
    repositories = Repositories.objects.all()
    serializer = RepositorySerializer(repositories, many=True)
    return JsonResponse(serializer.data, safe=False)

def points_list(request):
    point = Point.objects.all()
    serializer = PointSerializer(point, many=True)
    return JsonResponse(serializer.data, safe=False)






def verify_user(request):
    # if request.COOKIES.get('email_token'):
    #     email_token = request.COOKIES.get('email_token')
        
    # # Decode email token to get email
    # email = decoded_email_token['email']
    
        # Check if email token is expired

    # print("decoded_email_token")
    # print(decoded_email_token)
    
    
    if not request.COOKIES.get('email_token'):
        refresh_token = request.COOKIES.get('refresh_token')
            
        if not refresh_token:
            return JsonResponse({'error': 'Refresh token is missing'}, status=401)
            
        try:
            # Decode refresh token to get email
            decoded_refresh_token = jwt.decode(refresh_token, settings.JWT_REFRESH_SECRET_KEY, algorithms=['HS256'])
            
            
            if 'user_name' in decoded_refresh_token and 'email' in decoded_refresh_token:
                email = decoded_refresh_token['email']
                userName = decoded_refresh_token['user_name']
                payload = {
                'email': email,
                'user_name': userName,
                'exp': time.time()+settings.JWT_ACCESS_TOKEN_EXPIRATION
                }
                
                new_email_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
            
                # Update email token in cookies
                response = JsonResponse({'user_name': userName})
                response.set_cookie(
                'email_token',
                new_email_token,
                max_age=settings.JWT_ACCESS_TOKEN_EXPIRATION,
                httponly=True,
                secure=False,
                samesite=None
                )
                
                return response
            
            elif 'email' in decoded_refresh_token:
                email = decoded_refresh_token['email']
                
                
            # Generate a new email token with extended expiration
                payload = {
                'email': email,
                'exp': time.time()+settings.JWT_ACCESS_TOKEN_EXPIRATION
                }
                
                new_email_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
            
                # Update email token in cookies
                response = JsonResponse({'email': email})
                response.set_cookie(
                'email_token',
                new_email_token,
                max_age=settings.JWT_ACCESS_TOKEN_EXPIRATION,
                httponly=True,
                secure=False,
                samesite=None
                )
                
                return response
            else:
                return JsonResponse({'error': 'Token not found'}, status=401)
                
            
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Refresh token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid refresh token'}, status=401)
        
    
    elif request.COOKIES.get('email_token'):
        
        email_token = request.COOKIES.get('email_token')
        decoded_email_token = jwt.decode(email_token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
        
        
        if 'user_name' in decoded_email_token:
            userName = decoded_email_token['user_name']
            return JsonResponse({'user_name':userName})
    
        elif 'email' in decoded_email_token:
            email = decoded_email_token['email']
            return JsonResponse({'email':email})
    else:
        return JsonResponse({'error': 'No Token Found'}, status=401)






@require_POST
@csrf_exempt
def github_webhook(request):
    if request.method == 'POST':
        try:
            payload = json.loads(request.body)
            
            
            # Extract relevant data from the payload
            pr_data = payload.get('pull_request', {})
            repo_data = payload.get('repository', {})
            pr_title = pr_data.get('title')
            pr_html_url = pr_data.get('html_url')
            base_html_url = pr_data.get('base',{}).get('user',{}).get('html_url','')
            requester_name = pr_data.get('user', {}).get('login', '')
            pr_action = payload.get('action')
            pr_merged = pr_data.get('merged', False)  # Determine if the PR was merged
            
            # Handle pull request creation
            if pr_action == 'opened':
                # Check if a PullRequest record exists for the requester
                existing_pull_request, created = PullRequest.objects.get_or_create(
                    prId=pr_data['id'],  # Storing the GitHub PR ID
                    title=pr_title,
                    html_url=pr_html_url,
                    base_html_url=base_html_url,
                    requesterName=requester_name,
                    # You can also set the requestedTime field manually if needed
                    requestedTime=timezone.now(),
                )
                existing_pull_request.prStatus = 'Pending'
                print("UPDATED PENDING")
                existing_pull_request.repoName = repo_data.get('name', '')
                existing_pull_request.save()
                
                user = Point.objects.get(userName=requester_name)
                user.point+=3
                user.save()
                
                return JsonResponse({'status': 'created'})

            # Handle pull request merge
            elif pr_action == 'closed' and pr_merged:
                # Update the PR status and repository information
                existing_pull_request, created = PullRequest.objects.get_or_create(
                    prId=pr_data['id'],
                    defaults={
                        'title': pr_title,
                        'html_url': pr_html_url,
                        'requesterName': requester_name,
                        'requestedTime': timezone.now(),
                    }
                )
                existing_pull_request.prStatus = 'Merged'
                existing_pull_request.repoName = repo_data.get('name', '')
                existing_pull_request.save()
                
                user = Point.objects.get(userName=requester_name)
                user.point-=3
                user.point+=10
                user.save()
                
                
                
                return JsonResponse({'status': 'merged'})

        except Exception as e:
            print(f"Error processing webhook: {e}")
            return JsonResponse({'status': 'error'}, status=400)
    else:
        return JsonResponse({'status': 'invalid-method'}, status=405)





@csrf_exempt
@require_POST
def google_callback(request):
    try:
        body = json.loads(request.body)
        email = body.get('email')
        
        if RegisteredUser.objects.filter(email=email, userName=None).exists():
            user_exists = RegisteredUser.objects.filter(email=email).exists()
            
            payload = {
                'email': email,
                'exp': time.time()+settings.JWT_ACCESS_TOKEN_EXPIRATION
            }
            
            response = JsonResponse({'is_registered': user_exists})
            
            # Generate access token
            email_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
            
            # Generate refresh token (optional)
            refresh_payload = {
                'email': email,
                'exp': time.time()+settings.JWT_REFRESH_TOKEN_EXPIRATION
            }
            refresh_token = jwt.encode(refresh_payload, settings.JWT_REFRESH_SECRET_KEY, algorithm='HS256')
            
            # Set cookies for access token and refresh token
            response.set_cookie(
                'email_token',
                email_token,
                max_age=settings.JWT_ACCESS_TOKEN_EXPIRATION,
                httponly=True,
                secure=False,
                samesite=None
            )
            
            if refresh_token:
                response.set_cookie(
                    'refresh_token',
                    refresh_token,
                    max_age=settings.JWT_REFRESH_TOKEN_EXPIRATION,
                    httponly=True,
                    secure=False,
                    samesite=None
                )
            
            return response
        
        elif RegisteredUser.objects.filter(email=email).exists():
            user = RegisteredUser.objects.get(email=email)
            userName = user.userName
            
            payload = {
                'email': email,
                'user_name': userName,
                'exp': time.time()+settings.JWT_ACCESS_TOKEN_EXPIRATION
            }
            
            response = JsonResponse({'user_name': userName})
            
            # Generate access token
            email_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
            
            # Generate refresh token (optional)
            refresh_payload = {
                'email': email,
                'exp': time.time()+settings.JWT_REFRESH_TOKEN_EXPIRATION
            }
            refresh_token = jwt.encode(refresh_payload, settings.JWT_REFRESH_SECRET_KEY, algorithm='HS256')
            
            # Set cookies for access token and refresh token
            response.set_cookie(
                'email_token',
                email_token,
                max_age=settings.JWT_ACCESS_TOKEN_EXPIRATION,
                httponly=True,
                secure=False,
                samesite=None
            )
            
            if refresh_token:
                response.set_cookie(
                    'refresh_token',
                    refresh_token,
                    httponly=True,
                    max_age=settings.JWT_REFRESH_TOKEN_EXPIRATION,
                    secure=False,
                    samesite=None
                )
            # print(request.COOKIES.get('email_token'))
            
            return response
        
        else:
            return JsonResponse({'error': 'You haven\'t registered for SOC'}, status=401)
    
    except Exception as e:
        print(f'Error during Google callback: {e}')
        return JsonResponse({'error': 'An error occurred during authentication'}, status=500)

        
        
        
        
@csrf_exempt
@require_POST
def github_callback(request):
    try:
        body = json.loads(request.body)
        code = body.get('code')
        
        # Retrieve email token from cookies
        email_token = request.COOKIES.get('email_token')
        
        # Decode email token to get email
        decoded_email_token = jwt.decode(email_token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
        email = decoded_email_token['email']
        
        # Check if email token is expired
        if time.time() > decoded_email_token['exp']:
            # Email token is expired, try to refresh using refresh token
            refresh_token = request.COOKIES.get('refresh_token')
            
            if not refresh_token:
                return JsonResponse({'error': 'Refresh token is missing'}, status=401)
            
            try:
                # Decode refresh token to get email
                decoded_refresh_token = jwt.decode(refresh_token, settings.JWT_REFRESH_SECRET_KEY, algorithms=['HS256'])
                refreshed_email = decoded_refresh_token['email']
                
                # Ensure the email from refresh token matches the email from email token
                if refreshed_email != email:
                    return JsonResponse({'error': 'Email mismatch between tokens'}, status=401)
                
                # Generate a new email token with extended expiration
                payload = {
                    'email': refreshed_email,
                    'exp': time.time()+settings.JWT_ACCESS_TOKEN_EXPIRATION
                }
                
                new_email_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
                
                # Update email token in cookies
                response = JsonResponse({'message': 'Email token refreshed successfully'})
                response.set_cookie(
                    'email_token',
                    new_email_token,
                    max_age=settings.JWT_ACCESS_TOKEN_EXPIRATION,
                    httponly=True,
                    secure=False,
                    samesite=None
                )
                
                # Continue with the refreshed email token
                email_token = new_email_token
            
            except jwt.ExpiredSignatureError:
                return JsonResponse({'error': 'Refresh token has expired'}, status=401)
            except jwt.InvalidTokenError:
                return JsonResponse({'error': 'Invalid refresh token'}, status=401)
        
        # Proceed with GitHub authentication
        if RegisteredUser.objects.filter(email=email).exists():
            if not code:
                return JsonResponse({'error': 'Code parameter is missing'}, status=400)
            
            # Exchange code for access token from GitHub
            response = requests.post('https://github.com/login/oauth/access_token', data={
                'client_id': settings.GITHUB_CLIENT_ID,
                'client_secret': settings.GITHUB_CLIENT_SECRET,
                'code': code,
            }, headers={'Accept': 'application/json'})
            
            access_token = response.json().get('access_token')
            
            if not access_token:
                return JsonResponse({'error': 'Failed to retrieve access token'}, status=400)
            
            # Use the access token to fetch user details from GitHub
            user_response = requests.get('https://api.github.com/user', headers={
                'Authorization': f'token {access_token}'
            })
            
            github_user_data = user_response.json()
            userName = github_user_data['login']
            
            # Update user's username in RegisteredUser model
            user = RegisteredUser.objects.get(email=email)
            user.userName = userName
            user.save()
            
            # Generate JWT tokens
            payload = {
                'email': email,
                'user_name': userName,
                'exp': time.time()+settings.JWT_ACCESS_TOKEN_EXPIRATION
            }
            
            # Generate access token
            email_token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
            
            # Set cookies for access token
            response = JsonResponse({'user_name': userName})
            response.set_cookie(
                'email_token',
                email_token,
                max_age=settings.JWT_ACCESS_TOKEN_EXPIRATION,
                httponly=True,
                secure=False,
                samesite=None
            )
            
            return response
        
        else:
            return JsonResponse({'error': 'You haven\'t registered for SOC'}, status=401)
    
    except Exception as e:
        print(f'Error during GitHub callback: {e}')
        return JsonResponse({'error': 'An error occurred during authentication'}, status=500)
