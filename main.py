# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""This is a sample Hello World API implemented using Google Cloud
Endpoints."""

# [START imports]
import endpoints
from protorpc import message_types
from protorpc import messages
from protorpc import remote
# [END imports]

import google.auth.transport.requests
import json
import os

HTTP_REQUEST = google.auth.transport.requests.Request()


# [START messages]
class EchoRequest(messages.Message):
    content = messages.StringField(1)


class EchoResponse(messages.Message):
    """A proto Message that contains a simple string field."""
    content = messages.StringField(1)


ECHO_RESOURCE = endpoints.ResourceContainer(
    EchoRequest,
    n=messages.IntegerField(2, default=1))
# [END messages]


# [START echo_api]
@endpoints.api(
    name='echo',
    version='v1',
    issuers={'firebase': endpoints.Issuer(
        'https://securetoken.google.com/globalcity-auth-20',
        'https://www.googleapis.com/service_accounts/v1/metadata/x509/securetoken@system.gserviceaccount.com')})
class EchoApi(remote.Service):

    @endpoints.method(
        # This method takes a ResourceContainer defined above.
        ECHO_RESOURCE,
        # This method returns an Echo message.
        EchoResponse,
        path='echo',
        http_method='POST',
        name='echo')
    def echo(self, request):
        output_content = ' '.join([request.content] * request.n)
        return EchoResponse(content=output_content)

    @endpoints.method(
        # This method takes a ResourceContainer defined above.
        ECHO_RESOURCE,
        # This method returns an Echo message.
        EchoResponse,
        path='echo/{n}',
        http_method='POST',
        name='echo_path_parameter')
    def echo_path_parameter(self, request):
        output_content = ' '.join([request.content] * request.n)
        return EchoResponse(content=output_content)

    @endpoints.method(
        # This method takes a ResourceContainer defined above.
        message_types.VoidMessage,
        # This method returns an Echo message.
        EchoResponse,
        path='echo/getApiKey',
        http_method='GET',
        name='echo_api_key')
    def echo_api_key(self, request):
        return EchoResponse(content=request.get_unrecognized_field_info('key'))

    @endpoints.method(
        # This method takes an empty request body.
        message_types.VoidMessage,
        # This method returns an Echo message.
        EchoResponse,
        path='echo/getUserEmail',
        http_method='GET',
        # OAuth2 audiences allowed in incoming tokens.
        audiences={"firebase": ["globalcity-auth-20"]})
    def get_user_email(self, request):
        user = os.environ.get("google.api.auth.user_info")

        #id_token = request.headers['Authorization'].split(' ').pop()
        id_token = self.request_state.headers.get('Authorization').split(' ').pop()
        print("Token: "+id_token)
        #claims = google.oauth2.id_token.verify_firebase_token(id_token, HTTP_REQUEST)

        #s = json.dumps(claims)

        # If there's no user defined, the request was unauthenticated, so we
        # raise 401 Unauthorized.
        if not user:
            raise endpoints.UnauthorizedException
        print("User Email: "+str(user.email()))
        print("User ID: "+str(user.user_id()))
        print("Auth Domain: "+str(user.auth_domain()))
        return EchoResponse(content=user.email())
# [END echo_api]


# [START api_server]
api = endpoints.api_server([EchoApi])
# [END api_server]
