import logging
import re

from django.contrib.auth.hashers import PBKDF2PasswordHasher

from bookwyrm.models import User


class ApiKeyMiddleware:
    """authenticate a request using an API key in an Authorization: Bearer header"""
    def __init__(self, get_response):
        self.get_response = get_response
        self.log = logging.getLogger(__name__)
        self.hasher = PBKDF2PasswordHasher()

    def __call__(self, request):
        if not request.user.is_authenticated:
            auth = request.META.get("HTTP_AUTHORIZATION")
            if auth is not None:
                ip = request.META.get("REMOTE_ADDR")
                match = re.fullmatch("bearer\\s+([^:]+):(.+)", auth, re.I)
                log_suffix = ip
                resist_timing_attacks = True
                if match is not None:
                    username = match.group(1)
                    token = match.group(2)
                    log_suffix = username + " " + ip
                    if username is not None and token is not None:
                        try:
                            user = User.objects.get(username=username)
                        except User.DoesNotExist:
                            self.log.warning("[ApiKeyMiddleware] User does not exist: " + log_suffix)
                        else:
                            if user.api_key is None or user.api_key == "" or not user.is_active:
                                self.log.warning("[ApiKeyMiddleware] User has no key or is inactive: " + log_suffix)
                            else:
                                resist_timing_attacks = False
                                if self.hasher.verify(token, user.api_key):
                                    self.log.debug("[ApiKeyMiddleware] Good API key: " + log_suffix)
                                    request.user = user
                                else:
                                    self.log.warning("[ApiKeyMiddleware] Bad API key: " + log_suffix)
                    else:
                        self.log.warning("[ApiKeyMiddleware] Mismatched Authorization header: " + log_suffix)
                else:
                    self.log.warning("[ApiKeyMiddleware] Unknown Authorization header: " + log_suffix)
                if resist_timing_attacks:
                    self.hasher.encode("bogus", "bogus")
        return self.get_response(request)
