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
from .models import PullRequest

# Create your views here.
def index(request):
    pull = PullRequest.objects.all()
    return render(request, 'index.html', {'pull': pull})

def pull_requests_list(request):
    pull_requests = PullRequest.objects.all()
    serializer = PullRequestSerializer(pull_requests, many=True)
    return JsonResponse(serializer.data, safe=False)

def repositories_list(request):
    repository = Repositories.objects.all()
    serializer = RepositorySerializer(repository, many=True)
    return JsonResponse(serializer.data, safe=False)

def points_list(request):
    point = Point.objects.all()
    serializer = PointSerializer(point, many=True)
    return JsonResponse(serializer.data, safe=False)

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
                existing_pull_request.pr_status = 'Pending'
                existing_pull_request.repo = repo_data.get('name', '')
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
                existing_pull_request.pr_status = 'Merged'
                existing_pull_request.repo = repo_data.get('name', '')
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
        print(f"body:",body)
        print(f"email:",email)
    
        if RegisteredUser.objects.filter(email=email,userName=None).exists():
            user_exists = RegisteredUser.objects.filter(email=email).exists()
            
            payload = {
                'email': email,
                'exp': int(time.time()) + 3600
            }
            print(f"Userexits:,{user_exists}")
            response = JsonResponse({'is_registered': user_exists})
            
            secret_key = settings.JWT_SECRET_KEY  # Ensure you have this setting
            jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        
        
            response.set_cookie(
                'email_token', 
                jwt_token, 
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
                'exp': int(time.time()) + 3600  # Token expires in 1 hour
            }
            response = JsonResponse({'user_name':userName})
            
            secret_key = settings.JWT_SECRET_KEY  # Ensure you have this setting
            jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        
        
            response.set_cookie(
                'email_token', 
                jwt_token, 
                httponly=True, 
                secure=False,
                samesite=None
                )
    
            return response
        else:
            return JsonResponse({'error': 'You haven\'t registered for SOC'}, status=401)
            
            

    except Exception as e:
        print(f'Error during Google callback: {e}')
        
        
        
        
@csrf_exempt
@require_POST
def github_callback(request):
    try:
        body = json.loads(request.body)
        code = body.get('code')
        email_token = request.COOKIES.get('email_token')
        print(f"TOKEN:{email_token}")
        
        
        decodedToken = jwt.decode(email_token, settings.JWT_SECRET_KEY,algorithms=['HS256'])
        print(f"Decoded Token:{decodedToken}")
        email = decodedToken['email']
        print(f"Decoded Email:{email}")
        
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
            print(f"Data: {github_user_data}")
            # print(github_user_data)
            userName = github_user_data['login']
            
            user = RegisteredUser.objects.get(email=email)
            user.userName = userName
            user.save()
            
            print(f"userName: {userName}")
            print(f"Email: {email}")

            # if RegisteredUser.objects.filter(userName=userName).exists():
            # Generate JWT token
            payload = {
                'email':email,
                'user_name': userName,
                'exp': int(time.time()) + 3600  # Token expires in 1 hour
            }
            
            secret_key = settings.JWT_SECRET_KEY  # Ensure you have this setting
            jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')

            # Return JSON response with the JWT token
            response = JsonResponse({'user_name':userName})
            
            secret_key = settings.JWT_SECRET_KEY  # Ensure you have this setting
            jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')
        
        
            response.set_cookie(
            'auth_token', 
            jwt_token, 
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
        return JsonResponse({'error': 'An error occurred during authentication'}, status=500)











# @csrf_exempt
# @require_POST
# def github_callback(request):
#     try:
#         body = json.loads(request.body)
#         code = body.get('code')
#         email = body.get('email')
        
#         if not code:
#             return JsonResponse({'error': 'Code parameter is missing'}, status=400)

#         # Exchange code for access token from GitHub
#         response = requests.post('https://github.com/login/oauth/access_token', data={
#             'client_id': settings.GITHUB_CLIENT_ID,
#             'client_secret': settings.GITHUB_CLIENT_SECRET,
#             'code': code,
#         }, headers={'Accept': 'application/json'})

#         access_token = response.json().get('access_token')

#         if not access_token:
#             return JsonResponse({'error': 'Failed to retrieve access token'}, status=400)

#         # Use the access token to fetch user details from GitHub
#         user_response = requests.get('https://api.github.com/user', headers={
#             'Authorization': f'token {access_token}'
#         })

#         github_user_data = user_response.json()
#         print(f"Data: {github_user_data}")
#         # print(github_user_data)
#         userName = github_user_data['login']
#         displayName = github_user_data.get('name', '')
#         email = github_user_data.get('email', '')
#         print(f"userName: {userName}")
#         print(f"Email: {email}")

#         if RegisteredUser.objects.filter(userName=userName).exists():
#             # Generate JWT token
#             payload = {
#                 'user_id': userName,
#                 'exp': int(time.time()) + 3600  # Token expires in 1 hour
#             }
            
#             secret_key = settings.JWT_SECRET_KEY  # Ensure you have this setting
#             jwt_token = jwt.encode(payload, secret_key, algorithm='HS256')

#             # Return JSON response with the JWT token
#             return JsonResponse({
#                 'username': userName,
#                 'jwtToken': jwt_token,
#                 'message': 'Authentication successful'
#             })
#         else:
#             return JsonResponse({'error': 'You haven\'t registered for SOC'}, status=401)
#     except Exception as e:
#         print(f'Error during GitHub callback: {e}')
#         return JsonResponse({'error': 'An error occurred during authentication'}, status=500)