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
import xmltodict

class CrowdAuthFailure(Exception):
    """A failure occurred while performing an authentication operation"""
    pass


class CrowdAuthDenied(Exception):
    """Crowd server refused to perform the operation"""
    pass


class CrowdUserExists(Exception):
    pass


class CrowdNoSuchUser(Exception):
    pass


class CrowdGroupExists(Exception):
    pass


class CrowdNoSuchGroup(Exception):
    pass


class CrowdError(Exception):
    """Generic exception when unexpected response encountered"""
    def __init__(self, message=None):
        if not message:
            message = "unexpected response from Crowd server"
        Exception.__init__(self, message)


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
    """

    def __init__(self, crowd_url, app_name, app_pass, ssl_verify=False):
        self.crowd_url = crowd_url
        self.app_name = app_name
        self.app_pass = app_pass
        self.rest_url = crowd_url.rstrip("/") + "/rest/usermanagement/1"

        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.session.auth = requests.auth.HTTPBasicAuth(app_name, app_pass)
        self.session.headers.update({
            "Content-type": "application/json",
            "Accept": "application/json"
        })

    def __str__(self):
        return "Crowd Server at %s" % self.crowd_url

    def __repr__(self):
        return "<CrowdServer('%s', '%s', '%s')>" % \
            (self.crowd_url, self.app_name, self.app_pass)

    def _get(self, *args, **kwargs):
        """Wrapper around Requests for GET requests

        Returns:
            Response:
                A Requests Response object
        """
        req = self.session.get(*args, **kwargs)
        return req

    def _post(self, *args, **kwargs):
        """Wrapper around Requests for POST requests

        Returns:
            Response:
                A Requests Response object
        """
        req = self.session.post(*args, **kwargs)
        return req

    def _delete(self, *args, **kwargs):
        """Wrapper around Requests for DELETE requests

        Returns:
            Response:
                A Requests Response object
        """
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

        Raises:
            CrowdError: If auth ping could not be completed.
        """

        url = self.rest_url + "/non-existent/location"
        response = self._get(url)

        if response.status_code == 401:
            return False

        if response.status_code == 404:
            # A 'not found' response indicates we passed app auth
            return True

        # An error encountered - problem with the Crowd server?
        raise CrowdError("unidentified problem")

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

            None: If received negative authentication response

        Raises:
            CrowdAuthFailure:
                If authentication attempt failed (other than negative response)
        """

        response = self._post(self.rest_url + "/authentication",
                              data=json.dumps({"value": password}),
                              params={"username": username})

        if response.status_code == 200:
            return response.json()

        if response.status_code == 400:
            j = response.json()
            raise CrowdAuthFailure(j['message'])

        raise CrowdError

    def get_session(self, username, password, remote="127.0.0.1"):
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

        Returns:
            dict:
                A dict mapping of user attributes if the application
                authentication was successful. See the Crowd
                documentation for the authoritative list of attributes.

        Raises:
            CrowdAuthFailure: If authentication failed.
        """

        params = {
            "username": username,
            "password": password,
            "validation-factors": {
                "validationFactors": [
                    {"name": "remote_address", "value": remote, }
                ]
            }
        }

        response = self._post(self.rest_url + "/session",
                              data=json.dumps(params),
                              params={"expand": "user"})

        if response.status_code == 201:
            return response.json()

        if response.status_code == 400:
            j = response.json()
            raise CrowdAuthFailure(j['message'])

        raise CrowdError

    def validate_session(self, token, remote="127.0.0.1"):
        """Validate a session token.

        Validate a previously acquired session token against the
        Crowd server. This may be a token provided by a user from
        a http cookie or by some other means.

        Args:
            token: The session token.

            remote: The remote address of the user.

        Returns:
            dict:
                A dict mapping of user attributes if the application
                authentication was successful. See the Crowd
                documentation for the authoritative list of attributes.

        Raises:
            CrowdAuthFailure: If authentication failed.
        """

        params = {
            "validationFactors": [
                {"name": "remote_address", "value": remote, }
            ]
        }

        url = self.rest_url + "/session/%s" % token
        response = self._post(url, data=json.dumps(params),
                              params={"expand": "user"})

        # If token validation failed for any reason raise exception
        if not response.ok:
            raise CrowdAuthFailure

        # Otherwise return the user object
        return response.json()

    def terminate_session(self, token):
        """Terminates the session token, effectively logging out the user
        from all crowd-enabled services.

        Args:
            token: The session token.

        Returns:
            True: If session terminated

        Raises:
            CrowdError: If authentication failed.
        """

        url = self.rest_url + "/session/%s" % token
        response = self._delete(url)

        if response.status_code == 204:
            return True

        raise CrowdError

    def add_user(self, username, **kwargs):
        """Add a user to the directory

        Args:
            username: The account username
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

        Raises:
            CrowdError: If authentication failed.
        """

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
        except KeyError as e:
            raise ValueError("missing %s" % e.message)

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

        # Crowd should return 201, 400 or 403

        if response.status_code == 201:
            return True

        if response.status_code == 400:
            # User already exists / no password given (but we checked that)
            raise CrowdUserExists

        if response.status_code == 403:
            raise CrowdAuthDenied("application is not allowed to create "
                                  "a new user")

        raise CrowdError

    def remove_user(self, username):
        """Remove a user from the directory

        Args:
            username: The account username

        Returns:
            True: Succeeded

        Raises:
            CrowdNoSuchUser: If user did not exist
            CrowdAuthDenied: If application not allowed to delete the user
        """

        response = self._delete(self.rest_url + "/user",
                             params={"username": username})

        # Crowd should return 204, 403 or 404

        if response.status_code == 204:
            return True

        if response.status_code == 403:
            raise CrowdAuthDenied("application is not allowed to delete user")

        if response.status_code == 404:
            # User did not exist
            raise CrowdNoSuchUser

        raise CrowdError

    def get_user(self, username):
        """Retrieve information about a user

        Returns:
            dict: User information

            None: If no such user

        Raises:
            CrowdError: If unexpected response from Crowd server
        """

        response = self._get(self.rest_url + "/user",
                             params={"username": username,
                                     "expand": "attributes"})

        if response.status_code == 200:
            return response.json()

        if response.status_code == 404:
            return None

        raise CrowdError

    def get_user_direct_group(self, username, groupname):
        """Retrieves the user that is a direct member of the specified group

        Returns:
            dict: User information

            None: If no such user in the group

        Raises:
            CrowdError: If unexpected response from Crowd server
        """

        response = self._get(self.rest_url + "/group/user/direct",
                             params={"groupname": groupname,
                                     "username": username})

        if response.status_code == 200:
            return response.json()

        if response.status_code == 404:
            return None

        raise CrowdError

    def get_child_group_direct(self, groupname):
        """Retrieves the groups that are direct children of the specified group

        Returns:
            List: Group names

            None: If no such group is found

        Raises:
            CrowdError: If unexpected response from Crowd server
        """

        response = self._get(self.rest_url + "/group/child-group/direct",
                             params={"groupname": groupname})

        if response.status_code == 200:
            return response.json()

        if response.status_code == 404:
            return None

        raise CrowdError

    def get_group_membership(self):
        """Retrieves full details of all group memberships, with users and nested groups.

        Returns:
            Dict: All group memberships

            None: If no such group is found

        Raises:
            CrowdError: If unexpected response from Crowd server
        """
        self.session.headers.update({
            "Content-type": "application/xml",
            "Accept": "application/xml"
        })

        response = self._get(self.rest_url + "/group/membership")

        if response.status_code == 200:
            return xmltodict.parse(response.content)

        if response.status_code == 404:
            return None

        raise CrowdError

    def get_group_users_direct(self, groupname):
        """Retrieves the users that are direct members of the specified group

        Returns:
            List: Users

            None: If no such group is found

        Raises:
            CrowdError: If unexpected response from Crowd server
        """

        response = self._get(self.rest_url + "/group/user/direct",
                             params={"groupname": groupname})

        if response.status_code == 200:
            return response.json()

        if response.status_code == 404:
            return None

        raise CrowdError

    def add_group(self, groupname, **kwargs):
        """Creates a group

        Returns:
            True: The group was created

        Raises:
            CrowdGroupExists: The group already exists
            CrowdAuthFail
            CrowdError: If unexpected response from Crowd server
        """

        data = {
                "name": groupname,
                "description": groupname,
                "active": True,
                "type": "GROUP"
               }
        # Put values from kwargs into data
        for k, v in kwargs.items():
            if k not in data:
                raise ValueError("invalid argument %s" % k)
            data[k] = v

        response = self._post(self.rest_url + "/group",
                              data=json.dumps(data))

        if response.status_code == 201:
            return True

        if response.status_code == 400:
            raise CrowdGroupExists

        if response.status_code == 403:
            raise CrowdAuthFailure

        raise CrowdError("status code %d" % response.status_code)


    def get_groups(self, username):
        """Retrieves a list of group names that have <username> as a
        direct member.

        Returns:
            list:
                A list of strings of group names.

            None: If user not found

        Raises:
            CrowdError: If unexpected response from Crowd server
        """

        response = self._get(self.rest_url + "/user/group/direct",
                             params={"username": username})

        if response.status_code == 200:
            return [g['name'] for g in response.json()['groups']]

        if response.status_code == 404:
            return None

        raise CrowdError

    def get_nested_groups(self, username):
        """Retrieve a list of all group names that have <username> as
        a direct or indirect member.

        Args:
            username: The account username.

        Returns:
            list:
                A list of strings of group names.

            None: If user not found

        Raises:
            CrowdError: If unexpected response from Crowd server
        """

        response = self._get(self.rest_url + "/user/group/nested",
                             params={"username": username})

        if response.status_code == 200:
            return [g['name'] for g in response.json()['groups']]

        if response.status_code == 404:
            return None

        raise CrowdError

    def get_nested_group_users(self, groupname):
        """Retrieves a list of all users that directly or indirectly
        belong to the given groupname.

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

    def add_user_to_group(self, username, groupname):
        """Make user a direct member of a group

        Args:
            username: The user name.
            groupname: The group name.

        Returns:
            True: If successful

        Raises:
            CrowdNoSuchUser: The user does not exist
            CrowdNoSuchGroup: The group does not exist
            CrowdUserExists: The user is already a member
            CrowdError: Unexpected response
        """
        response = self._post(self.rest_url + "/group/user/direct",
                              data=json.dumps({"name": username}),
                              params={"groupname": groupname})

        if response.status_code == 201:
            return True

        if response.status_code == 400:
            raise CrowdNoSuchUser

        if response.status_code == 404:
            raise CrowdNoSuchGroup

        if response.status_code == 409:
            raise CrowdUserExists

        raise CrowdError("received server response %d" % response.status_code)

    def add_child_group_to_group(self, parentgroupname, childgroupname):
        """Make user a direct member of a group

        Args:
            username: The user name.
            groupname: The group name.

        Returns:
            True: If successful

        Raises:
            CrowdNoSuchUser: The user does not exist
            CrowdNoSuchGroup: The group does not exist
            CrowdUserExists: The user is already a member
            CrowdError: Unexpected response
        """
        response = self._post(self.rest_url + "/group/child-group/direct",
                              data=json.dumps({"name": childgroupname}),
                              params={"groupname": parentgroupname})

        if response.status_code == 201:
            return True

        if response.status_code == 400:
            raise CrowdNoSuchUser

        if response.status_code == 404:
            raise CrowdNoSuchGroup

        raise CrowdError("received server response %d" % response.status_code)

    def remove_user_from_group(self, username, groupname):
        """Remove user as a direct member of a group

        Args:
            username: The user name.
            groupname: The group name.

        Returns:
            True: If successful

        Raises:
            CrowdNotFound: The user or group does not exist
            CrowdUserExists: The user is already a member
            CrowdError: Unexpected response
        """
        response = self._delete(self.rest_url + "/group/user/direct",
                              params={"groupname": groupname,
                                      "username": username})

        if response.status_code == 204:
            return True

        if response.status_code == 404:
            # user or group does not exist
            j = response.json()
            if j['message'].lower().startswith('group'):
                raise CrowdNoSuchGroup
            elif j['message'].lower().startswith('user'):
                raise CrowdNoSuchUser
            else:
                raise CrowdError("unknown server response")

        raise CrowdError

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

    def group_exists(self, group):
        """Determines if the group exists.

        Args:
            group: The group name.


        Returns:
            bool:
                True if the group exists in the Crowd application.
        """

        response = self._get(self.rest_url + "/group",
                             params={"groupname": group})

        if not response.ok:
            return None

        return True