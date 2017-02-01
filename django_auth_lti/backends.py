import logging
from time import time

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import PermissionDenied

from oauthlib.oauth1 import RequestValidator,SignatureOnlyEndpoint, SIGNATURE_RSA, SIGNATURE_HMAC
from oauthlib.oauth1.rfc5849 import signature,errors

logger = logging.getLogger(__name__)

class LTIRequestValidator(RequestValidator):
    enforce_ssl = False

    def validate_timestamp_and_nonce(client_key, timestamp, nonce, request, request_token=None, access_token=None):
        return True

    def validate_client_key(self,client_key,request):
        return client_key in settings.LTI_OAUTH_CREDENTIALS

    def get_client_secret(self,client_key,request):
        return settings.LTI_OAUTH_CREDENTIALS.get(client_key)

    def check_nonce(self,nonce):
        return set(nonce) <= self.safe_characters


class LTIEndpoint(SignatureOnlyEndpoint):
    resource_owner_secret = ''

    def validate_request(self, uri, http_method='GET',
                         body=None, headers=None):
        """Validate a signed OAuth request.
        :param uri: The full URI of the token request.
        :param http_method: A valid HTTP verb, i.e. GET, POST, PUT, HEAD, etc.
        :param body: The request body as a string.
        :param headers: The request headers as a dict.
        :returns: A tuple of 2 elements.
                  1. True if valid, False otherwise.
                  2. An oauthlib.common.Request object.
        """
        try:
            request = self._create_request(uri, http_method, body, headers)
        except errors.OAuth1Error:
            logger.error("Create request failed")
            return False, None

        try:
            self._check_transport_security(request)
            self._check_mandatory_parameters(request)
        except errors.OAuth1Error:
            logger.error("transport security or mandatory params failed")
            return False, request

        if not self.request_validator.validate_timestamp_and_nonce(
                request.client_key, request.timestamp, request.nonce, request):
            logger.error("timestamp and nonce not valid")
            return False, request

        # The server SHOULD return a 401 (Unauthorized) status code when
        # receiving a request with invalid client credentials.
        # Note: This is postponed in order to avoid timing attacks, instead
        # a dummy client is assigned and used to maintain near constant
        # time request verification.
        #
        # Note that early exit would enable client enumeration
        valid_client = self.request_validator.validate_client_key(
            request.client_key, request)
        if not valid_client:
            logger.error("not valid client")
            request.client_key = self.request_validator.dummy_client

        valid_signature = self._check_signature(request)

        # log the results to the validator_log
        # this lets us handle internal reporting and analysis
        request.validator_log['client'] = valid_client
        request.validator_log['signature'] = valid_signature

        # We delay checking validity until the very end, using dummy values for
        # calculations and fetching secrets/keys to ensure the flow of every
        # request remains almost identical regardless of whether valid values
        # have been supplied. This ensures near constant time execution and
        # prevents malicious users from guessing sensitive information
        v = all((valid_client, valid_signature))
        if not v:
            logger.info("[Failure] request verification failed.")
            logger.info("Valid client: %s", valid_client)
            logger.info("Valid signature: %s", valid_signature)
        return v, request

    def _check_signature(self, request, is_token_request=False):
        # ---- RSA Signature verification ----
        if request.signature_method == SIGNATURE_RSA:
            # The server verifies the signature per `[RFC3447] section 8.2.2`_
            # .. _`[RFC3447] section 8.2.2`: http://tools.ietf.org/html/rfc3447#section-8.2.1
            rsa_key = self.request_validator.get_rsa_key(
                request.client_key, request)
            logger.info("RSA: ".format(rsa_key))
            valid_signature = signature.verify_rsa_sha1(request, rsa_key)

        # ---- HMAC or Plaintext Signature verification ----
        else:
            # Servers receiving an authenticated request MUST validate it by:
            #   Recalculating the request signature independently as described in
            #   `Section 3.4`_ and comparing it to the value received from the
            #   client via the "oauth_signature" parameter.
            # .. _`Section 3.4`: http://tools.ietf.org/html/rfc5849#section-3.4
            client_secret = self.request_validator.get_client_secret(
                request.client_key, request)
            resource_owner_secret = self.resource_owner_secret

            logger.info("client secret: {}".format(client_secret))
            logger.info("owner secret: {}".format(resource_owner_secret))

            if request.signature_method == SIGNATURE_HMAC:
                logger.info("HMAC")
                valid_signature = signature.verify_hmac_sha1(request,
                                                             client_secret, resource_owner_secret)
            else:
                logger.info("PLAINTEXT")
                valid_signature = signature.verify_plaintext(request,
                                                             client_secret, resource_owner_secret)
        return valid_signature


class LTIAuthBackend(ModelBackend):

    """
    By default, the ``authenticate`` method creates ``User`` objects for
    usernames that don't already exist in the database.  Subclasses can disable
    this behavior by setting the ``create_unknown_user`` attribute to
    ``False``.
    """

    # Create a User object if not already in the database?
    create_unknown_user = True
    # Username prefix for users without an sis source id
    unknown_user_prefix = "cuid:"

    validator_class = LTIRequestValidator
    endpoint_class = LTIEndpoint

    def get_validator(self,validator_class=None):
        if validator_class==None:
            validator_class = self.validator_class
        return validator_class()

    def get_endpoint(self,endpoint_class=None):
        if endpoint_class==None:
            endpoint_class = self.endpoint_class
        return endpoint_class(**self.get_endpoint_kwargs())

    def get_endpoint_kwargs(self):
        return {'request_validator': self.get_validator()}

    def authenticate(self, request):

        request_key = request.POST.get('oauth_consumer_key', None)

        if request_key is None:
            logger.error("Request doesn't contain an oauth_consumer_key; can't continue.")
            return None

        validator = self.get_validator()
        endpoint = self.get_endpoint()

        secret = validator.get_client_secret(request_key,request)

        if secret is None:
            logger.error("Could not get a secret for key %s" % request_key)
            raise PermissionDenied

        logger.debug('using key/secret %s/%s' % (request_key, secret))

        headers = {k:v for k,v in request.META.items() if type(v)==str}
        for k,v in request.META.items():
            if k.lower() in ['content_type','content-type']:
                headers['Content-Type'] = v

        request_is_valid,_ = endpoint.validate_request(
            request.build_absolute_uri(),
            request.method,
            request.POST.dict(),
            headers
        )

        if not request_is_valid:
            logger.error("Invalid request: signature check failed.")
            raise PermissionDenied

        # if we got this far, the user is good

        user = None

        # Retrieve username from LTI parameter or default to an overridable function return value

        username = request.POST.get('lis_person_sourcedid') or self.get_default_username(
            request, prefix=self.unknown_user_prefix)
        username = self.clean_username(username)  # Clean it

        email = request.POST.get('lis_person_contact_email_primary')
        first_name = request.POST.get('lis_person_name_given')
        last_name = request.POST.get('lis_person_name_family')

        UserModel = get_user_model()

        # Note that this could be accomplished in one try-except clause, but
        # instead we use get_or_create when creating unknown users since it has
        # built-in safeguards for multiple threads.
        if self.create_unknown_user:
            user, created = UserModel.objects.get_or_create(**{
                UserModel.USERNAME_FIELD: username,
            })

            if created:
                logger.debug('authenticate created a new user for %s' % username)
            else:
                logger.debug('authenticate found an existing user for %s' % username)

        else:
            logger.debug(
                'automatic new user creation is turned OFF! just try to find and existing record')
            try:
                user = UserModel.objects.get_by_natural_key(username)
            except UserModel.DoesNotExist:
                logger.debug('authenticate could not find user %s' % username)
                # should return some kind of error here?
                pass

        # update the user
        if email:
            user.email = email
        if first_name:
            user.first_name = first_name
        if last_name:
            user.last_name = last_name
        user.save()
        logger.debug("updated the user record in the database")

        return user

    def clean_username(self, username):
        return username[:25]

    def get_default_username(self, request, prefix=''):
        """
        Return a default username value in case offical
        LTI param lis_person_sourcedid was not present.
        """
        # Default back to user_id lti param
        uname = request.POST.get('canvas_user_id') or request.POST.get('user_id')
        if uname is None:
            raise Exception("No user-identifying information is present in the LTI launch data")
        return prefix + uname
