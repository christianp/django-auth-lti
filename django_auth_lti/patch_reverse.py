"""
Monkey-patch django.urls.reverse to add resource_link_id to all URLs
"""
from urllib.parse import urlparse, urlunparse, parse_qs
from urllib.parse import urlencode

from django import urls

from .thread_local import get_current_request


django_reverse = None


def reverse(*args, **kwargs):
    """
    Call django's reverse function and append the current resource_link_id as a query parameter

    :param kwargs['exclude_resource_link_id']: Do not add the resource link id as a query parameter
    :returns Django named url
    """
    request = get_current_request()

    # Check for custom exclude_resource_link_id kwarg and remove it before passing kwargs to django reverse
    exclude_resource_link_id = kwargs.pop('exclude_resource_link_id', False)

    url = django_reverse(*args, **kwargs)
    if not exclude_resource_link_id:
        # Append resource_link_id query param if exclude_resource_link_id kwarg was not passed or is False
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if 'resource_link_id' not in query.keys():
            resource_link_id = request.LTI.get('resource_link_id')
            if resource_link_id is not None:
                query['resource_link_id'] = resource_link_id
                url = urlunparse(
                    (parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query), parsed.fragment)
                )
    return url


def patch_reverse():
    """
    Monkey-patches the django.urls.reverse function. Will not patch twice.
    """
    global django_reverse
    if urls.reverse is not reverse:
        django_reverse = urls.reverse
        urls.reverse = reverse


patch_reverse()
