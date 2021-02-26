# Copyright 2012 Alexander Else <aelse@else.id.au>.
#
# This file is part of the python-crowd library.
#
# python-crowd is free software released under the BSD License.
# Please see the LICENSE file included in this distribution for
# terms of use. This LICENSE is also available at
# https://github.com/aelse/python-crowd/blob/master/LICENSE

import json
import requests
from lxml import etree


class CrowdServer(object):
    """Crowd server authentication object.

    This is a Crowd authentication class to be configured for a
    particular application (app_name) to authenticate users
    against a Crowd server (crowd_url).

    This module uses the Crowd JSON API for talking to Crowd.

    An application account must be configured in the Crowd server
    and permitted to authenticate users against one or more user
    directories prior to using this module.

    Please see the Crowd documentation for information about
    configuring additional applications to talk to Crowd.

    The ``ssl_verify`` parameter controls how and if certificates are verified.
    If ``True``, the SSL certificate will be verified.
    A CA_BUNDLE path can also be provided.

    The ``client_cert`` tuple (cert,key) specifies a SSL client certificate and key files.
    """

    def __init__(self, crowd_url, app_name, app_pass, ssl_verify=True,
                 timeout=None, client_cert=None):
        self.crowd_url = crowd_url
        self.app_name = app_name
        self.app_pass = app_pass
        self.rest_url = crowd_url.rstrip("/") + "/rest/usermanagement/1"
        self.ssl_verify = ssl_verify
        self.client_cert = client_cert
        self.timeout = timeout

        self.session = self._build_session(content_type='json')
        self.session_xml = self._build_session(content_type='xml')

    def __str__(self):
        return "Crowd Server at %s" % self.crowd_url

    # don't include the password!
    def __repr__(self):
        return "<CrowdServer('%s', '%s', '********')>" % \
            (self.crowd_url, self.app_name)

    def _build_session(self, content_type='json'):
        headers = {
            'Content-Type': 'application/{}'.format(content_type),
            'Accept': 'application/{}'.format(content_type),
        }
        session = requests.Session()
        session.verify = self.ssl_verify
        session.cert = self.client_cert
        session.auth = requests.auth.HTTPBasicAuth(self.app_name, self.app_pass)
        session.headers.update(headers)
        return session

    def _get(self, *args, **kwargs):
        """Wrapper around Requests for GET requests

        Returns:
            Response:
                A Requests Response object
        """

        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        req = self.session.get(*args, **kwargs)
        return req

    def _get_xml(self, *args, **kwargs):
        """Wrapper around Requests for GET XML requests

        Returns:
            Response:
                A Requests Response object
        """
        req = self.session_xml.get(*args, **kwargs)
        return req

    def _post(self, *args, **kwargs):
        """Wrapper around Requests for POST requests

        Returns:
            Response:
                A Requests Response object
        """

        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        req = self.session.post(*args, **kwargs)
        return req

    def _post_xml(self, *args, **kwargs):
        """Wrapper around Requests for POST requests

        Returns:
            Response:
                A Requests Response object
        """

        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        req = self.session_xml.post(*args, **kwargs)
        return req

    def _put(self, *args, **kwargs):
        """Wrapper around Requests for PUT requests

        Returns:
            Response:
                A Requests Response object
        """

        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        req = self.session.put(*args, **kwargs)
        return req

    def _delete(self, *args, **kwargs):
        """Wrapper around Requests for DELETE requests

        Returns:
            Response:
                A Requests Response object
        """

        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout

        req = self.session.delete(*args, **kwargs)
        return req

    def auth_ping(self):
        """Test that application can authenticate to Crowd.

        Attempts to authenticate the application user against
        the Crowd server. In order for user authentication to
        work, an application must be able to authenticate.

        Returns:
            bool:
                True if the application authentication succeeded.
        """

        url = self.rest_url + "/non-existent/location"
        response = self._get(url)

        if response.status_code == 401:
            return False
        elif response.status_code == 404:
            return True
        else:
            # An error encountered - problem with the Crowd server?
            return False

    def auth_user(self, username, password):
        """Authenticate a user account against the Crowd server.

        Attempts to authenticate the user against the Crowd server.

        Args:
            username: The account username.

            password: The account password.

        Returns:
            dict:
                A dict mapping of user attributes if the application
                authentication was successful. See the Crowd documentation
                for the authoritative list of attributes.

            None: If authentication failed.
        """

        response = self._post(self.rest_url + "/authentication",
                              data=json.dumps({"value": password}),
                              params={"username": username})

        # If authentication failed for any reason return None
        if not response.ok:
            return None

        # ...otherwise return a dictionary of user attributes
        return response.json()

    def get_session(self, username, password, remote="127.0.0.1", proxy=None):
        """Create a session for a user.

        Attempts to create a user session on the Crowd server.

        Args:
            username: The account username.

            password: The account password.

            remote:
                The remote address of the user. This can be used
                to create multiple concurrent sessions for a user.
                The host you run this program on may need to be configured
                in Crowd as a trusted proxy for this to work.

            proxy: Value of X-Forwarded-For server header.

        Returns:
            dict:
                A dict mapping of user attributes if the application
                authentication was successful. See the Crowd
                documentation for the authoritative list of attributes.

            None: If authentication failed.
        """

        params = {
            "username": username,
            "password": password,
            "validation-factors": {
                "validationFactors": [
                    {"name": "remote_address", "value": remote, },
                ]
            }
        }

        if proxy:
            params["validation-factors"]["validationFactors"].append({"name": "X-Forwarded-For", "value": proxy, })

        response = self._post(self.rest_url + "/session",
                              data=json.dumps(params),
                              params={"expand": "user"})

        # If authentication failed for any reason return None
        if not response.ok:
            return None

        # Otherwise return the user object
        return response.json()

    def validate_session(self, token, remote="127.0.0.1", proxy=None):
        """Validate a session token.

        Validate a previously acquired session token against the
        Crowd server. This may be a token provided by a user from
        a http cookie or by some other means.

        Args:
            token: The session token.

            remote: The remote address of the user.

            proxy: Value of X-Forwarded-For server header

        Returns:
            dict:
                A dict mapping of user attributes if the application
                authentication was successful. See the Crowd
                documentation for the authoritative list of attributes.

            None: If authentication failed.
        """

        params = {
            "validationFactors": [
                {"name": "remote_address", "value": remote, },
            ]
        }

        if proxy:
            params["validationFactors"].append({"name": "X-Forwarded-For", "value": proxy, })

        url = self.rest_url + "/session/%s" % token
        response = self._post(url, data=json.dumps(params), params={"expand": "user"})

        # For consistency between methods use None rather than False
        # If token validation failed for any reason return None
        if not response.ok:
            return None

        # Otherwise return the user object
        return response.json()

    def terminate_session(self, token):
        """Terminates the session token, effectively logging out the user
        from all crowd-enabled services.

        Args:
            token: The session token.

        Returns:
            True: If session terminated

            None: If session termination failed
        """

        url = self.rest_url + "/session/%s" % token
        response = self._delete(url)

        # For consistency between methods use None rather than False
        # If token validation failed for any reason return None
        if not response.ok:
            return None

        # Otherwise return True
        return True

    def add_user(self, username, raise_on_error=False, **kwargs):
        """Add a user to the directory

        Args:
            username: The account username
            raise_on_error: optional (default: False)
            **kwargs: key-value pairs:
                          password: mandatory
                          email: mandatory
                          first_name: optional
                          last_name: optional
                          display_name: optional
                          active: optional (default True)

        Returns:
            True: Succeeded
            False: If unsuccessful
        """
        # Check that mandatory elements have been provided
        if 'password' not in kwargs:
            raise ValueError("missing password")
        if 'email' not in kwargs:
            raise ValueError("missing email")

        # Populate data with default and mandatory values.
        # A KeyError means a mandatory value was not provided,
        # so raise a ValueError indicating bad args.
        try:
            data = {
                    "name": username,
                    "first-name": username,
                    "last-name": username,
                    "display-name": username,
                    "email": kwargs["email"],
                    "password": {"value": kwargs["password"]},
                    "active": True
                   }
        except KeyError:
            return ValueError

        # Remove special case 'password'
        del(kwargs["password"])

        # Put values from kwargs into data
        for k, v in kwargs.items():
            new_k = k.replace("_", "-")
            if new_k not in data:
                raise ValueError("invalid argument %s" % k)
            data[new_k] = v

        response = self._post(self.rest_url + "/user",
                              data=json.dumps(data))

        if response.status_code == 201:
            return True

        if raise_on_error:
            raise RuntimeError(response.json()['message'])

        return False

    def get_user(self, username):
        """Retrieve information about a user

        Returns:
            dict: User information

            None: If no user or failure occurred
        """

        response = self._get(self.rest_url + "/user",
                             params={"username": username,
                                     "expand": "attributes"})

        if not response.ok:
            return None

        return response.json()

    def set_active(self, username, active_state):
        """Set the active state of a user

        Args:
            username: The account username
            active_state: True or False

        Returns:
            True: If successful
            None: If no user or failure occurred
        """

        if active_state not in (True, False):
            raise ValueError("active_state must be True or False")

        user = self.get_user(username)
        if user is None:
            return None

        if user['active'] is active_state:
            # Already in desired state
            return True

        user['active'] = active_state
        response = self._put(self.rest_url + "/user",
                             params={"username": username},
                             data=json.dumps(user))

        if response.status_code == 204:
            return True

        return None

    def set_user_attribute(self, username, attribute, value, raise_on_error=False):
        """Set an attribute on  a user
        :param username: The username on which to set the attribute
        :param attribute: The name of the attribute to set
        :param value: The value of the attribute to set
        :return: True on success, False on failure.
        """
        data = {
            'attributes': [
                {
                    'name': attribute,
                    'values': [
                        value
                    ]
                },
            ]
        }
        response = self._post(self.rest_url + "/user/attribute",
                              params={"username": username,},
                              data=json.dumps(data))

        if response.status_code == 204:
            return True

        if raise_on_error:
            raise RuntimeError(response.json()['message'])

        return False

    def add_user_to_group(self, username, groupname, raise_on_error=False):
        """Add a user to a group
        :param username: The username to assign to the group
        :param groupname: The group name into which to assign the user
        :return: True on success, False on failure.
        """
        data = {
                'name': groupname,
        }
        response = self._post(self.rest_url + "/user/group/direct",
                              params={"username": username,},
                              data=json.dumps(data))

        if response.status_code == 201:
            return True

        if raise_on_error:
            raise RuntimeError(response.json()['message'])

        return False

    def remove_user_from_group(self, username, groupname, raise_on_error=False):
        """Remove a user from a group

	Attempts to remove a user from a group

	Args
             username: The username to remove from the group.
             groupname: The group name to be removed from the user.

        Returns:
            True: Succeeded
            False: If unsuccessful
        """

        response = self._delete(self.rest_url + "/group/user/direct",params={"username": username, "groupname": groupname})

        if response.status_code == 204:
            return True

        if raise_on_error:
            raise RuntimeError(response.json()['message'])

        return False

    def change_password(self, username, newpassword, raise_on_error=False):
        """Change new password for a user

        Args:
            username: The account username.

            newpassword: The account new password.

            raise_on_error: optional (default: False)

        Returns:
            True: Succeeded
            False: If unsuccessful
        """

        response = self._put(self.rest_url + "/user/password",
                             data=json.dumps({"value": newpassword}),
                             params={"username": username})

        if response.ok:
            return True

        if raise_on_error:
            raise RuntimeError(response.json()['message'])

        return False

    def send_password_reset_link(self, username):
        """Sends the user a password reset link (by email)

        Args:
            username: The account username.

        Returns:
            True: Succeeded
            False: If unsuccessful
        """

        response = self._post(self.rest_url + "/user/mail/password",
                              params={"username": username})

        if response.ok:
            return True

        return False

    def get_groups(self, username):
        """Retrieves a list of group names that have <username> as a direct member.

        Returns:
            list:
                A list of strings of group names.
        """

        response = self._get(self.rest_url + "/user/group/direct",
                             params={"username": username})

        if not response.ok:
            return None

        return [g['name'] for g in response.json()['groups']]

    def get_nested_groups(self, username):
        """Retrieve a list of all group names that have <username> as a direct or indirect member.

        Args:
            username: The account username.


        Returns:
            list:
                A list of strings of group names.
        """

        response = self._get(self.rest_url + "/user/group/nested",
                             params={"username": username})

        if not response.ok:
            return None

        return [g['name'] for g in response.json()['groups']]

    def get_nested_group_users(self, groupname):
        """Retrieves a list of all users that directly or indirectly belong to the given groupname.

        Args:
            groupname: The group name.


        Returns:
            list:
                A list of strings of user names.
        """

        response = self._get(self.rest_url + "/group/user/nested",
                             params={"groupname": groupname,
                                     "start-index": 0,
                                     "max-results": 99999})

        if not response.ok:
            return None

        return [u['name'] for u in response.json()['users']]

    def user_exists(self, username):
        """Determines if the user exists.

        Args:
            username: The user name.


        Returns:
            bool:
                True if the user exists in the Crowd application.
        """

        response = self._get(self.rest_url + "/user",
                             params={"username": username})

        if not response.ok:
            return None

        return True

    def get_memberships(self):
        """Fetches all group memberships.

        Returns:
            dict:
        key: group name
        value: (array of users, array of groups)
        """

        response = self._get_xml(self.rest_url + "/group/membership")

        if not response.ok:
            return None

        xmltree = etree.fromstring(response.content)
        memberships = {}
        for mg in xmltree.findall('membership'):
            # coerce values to unicode in a python 2 and 3 compatible way
            group = u'{}'.format(mg.get('group'))
            users = [u'{}'.format(u.get('name')) for u in mg.find('users').findall('user')]
            groups = [u'{}'.format(g.get('name')) for g in mg.find('groups').findall('group')]
            memberships[group] = {u'users': users, u'groups': groups}
        return memberships

    def search(self, entity_type, property_name, search_string,
               start_index=0, max_results=99999, with_attributes=False):
        """Performs a user search using the Crowd search API.

        https://developer.atlassian.com/display/CROWDDEV/Crowd+REST+Resources#CrowdRESTResources-SearchResource

        Args:
            entity_type: 'user' or 'group'
            property_name: eg. 'email', 'name'
            search_string: the string to search for.
            start_index: starting index of the results (default: 0)
            max_results: maximum number of results returned (default: 99999)
            with_attributes: whether also to return entity attributes

        Returns:
            json results:
                Returns search results.
        """

        # optionally return attributes (might expect <entity-type>.attributes
        # but that doesn't work and this does)
        expand = entity_type
        if with_attributes:
            expand += ",attributes"

        params = {
            'entity-type': entity_type,
            'expand': expand,
            'start-index': start_index,
            'max-results': max_results
        }

        # Construct XML payload of the form:
        # <property-search-restriction>
        #   <property>
        #     <name>email</name>
        #     <type>STRING</type>
        #   </property>
        #   <match-mode>CONTAINS</match-mode>
        #   <value>bob@example.net</value>
        # </property-search-restriction>

        root = etree.Element('property-search-restriction')

        property_ = etree.Element('property')
        prop_name = etree.Element('name')
        prop_name.text = property_name
        property_.append(prop_name)
        prop_type = etree.Element('type')
        prop_type.text = 'STRING'
        property_.append(prop_type)
        root.append(property_)

        match_mode = etree.Element('match-mode')
        match_mode.text = 'CONTAINS'
        root.append(match_mode)

        value = etree.Element('value')
        value.text = search_string
        root.append(value)

        # Construct the XML payload expected by search API
        payload = '<?xml version="1.0" encoding="UTF-8"?>\n' + etree.tostring(root).decode('utf-8')

        # We're sending XML but would like a JSON response
        session = self._build_session(content_type='xml')
        session.headers.update({'Accept': 'application/json'})
        response = session.post(self.rest_url + "/search", params=params, data=payload, timeout=self.timeout)

        if not response.ok:
            return None

        return response.json()
