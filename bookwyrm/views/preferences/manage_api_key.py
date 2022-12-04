from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import PBKDF2PasswordHasher
from django.template.response import TemplateResponse
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.views import View


@method_decorator(login_required, name="dispatch")
class ManageApiKey(View):
    """create or revoke an API key as a signed-in user"""

    def get(self, request):
        """manage API key page"""
        data = {"state": "show"}
        return TemplateResponse(request, "preferences/manage_api_key.html", data)

    def post(self, request):
        """create a new API key, or revoke an existing key"""
        action = request.POST.get("action")
        if action == "revoke":
            request.user.api_key = None
            request.user.save(broadcast=False, update_fields=["api_key"])
            data = {"state": "revoked"}
        elif action == "generate":
            bearer_token = get_random_string(32)
            salt = get_random_string(16)
            hasher = PBKDF2PasswordHasher()
            request.user.api_key = hasher.encode(bearer_token, salt)
            request.user.save(broadcast=False, update_fields=["api_key"])
            data = {"bearer_token": request.user.username + ":" + bearer_token, "state": "generated"}
        else:
            data = {"state": "error"}
        return TemplateResponse(request, "preferences/manage_api_key.html", data)
