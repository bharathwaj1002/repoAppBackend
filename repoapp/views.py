from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.utils import timezone
from .serializers import PullRequestSerializer
import json

from.models import PullRequest

# Create your views here.
def index(request):
    pull = PullRequest.objects.all()
    return render(request, 'index.html', {'pull': pull})

def pull_requests_list(request):
    pull_requests = PullRequest.objects.all()
    serializer = PullRequestSerializer(pull_requests, many=True)
    return JsonResponse(serializer.data, safe=False)

@require_POST
@csrf_exempt
def github_webhook(request):
    if request.method == 'POST':
        try:
            payload = json.loads(request.body)
            print("Received a webhook:", payload)
            
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
                    id=pr_data['id'],  # Storing the GitHub PR ID
                    title=pr_title,
                    html_url=pr_html_url,
                    base_html_url=base_html_url,
                    requester_name=requester_name,
                    # You can also set the created_at field manually if needed
                    created_at=timezone.now(),
                )
                existing_pull_request.pr_status = 'Pending'
                existing_pull_request.repo = repo_data.get('name', '')
                existing_pull_request.save()
                
                return JsonResponse({'status': 'created'})

            # Handle pull request merge
            elif pr_action == 'closed' and pr_merged:
                # Update the PR status and repository information
                existing_pull_request, created = PullRequest.objects.get_or_create(
                    id=pr_data['id'],
                    defaults={
                        'title': pr_title,
                        'html_url': pr_html_url,
                        'requester_name': requester_name,
                        'created_at': timezone.now(),
                    }
                )
                existing_pull_request.pr_status = 'Merged'
                existing_pull_request.repo = repo_data.get('name', '')
                existing_pull_request.save()
                
                return JsonResponse({'status': 'merged'})

        except Exception as e:
            print(f"Error processing webhook: {e}")
            return JsonResponse({'status': 'error'}, status=400)
    else:
        return JsonResponse({'status': 'invalid-method'}, status=405)