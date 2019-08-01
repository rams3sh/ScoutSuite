import boto3
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session

from ScoutSuite.providers.base.authentication_strategy import AuthenticationStrategy, AuthenticationException


class AWSAuthenticationStrategy(AuthenticationStrategy):
    """
    Implements authentication for the AWS provider
    """


    def __init__(self):

        """
        This initiates the variables supported for authentication for AyanR
        """

        self.profile = None
        self.aws_access_key_id = None
        self.aws_secret_access_key = None
        self.role_arn = None
        self.session_name = None

    def authenticate(self, profile=None, aws_access_key_id=None, aws_secret_access_key=None, role_arn=None,
                     session_name=None, **kwargs):
        """
                This function will return Session instead of credentials for AWS.
                This will help in case of refreshing credentials implemented from boto3 as the Refreshing Credentials works
                only for session and not credentials.
        """

        self.profile = profile
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.role_arn = role_arn
        self.session_name = session_name

        try:
            if profile:
                session = boto3.Session(profile_name=profile)

                # Test querying for current user
                sts_client = session.client('sts')
                sts_client.get_caller_identity()
                return session

            elif aws_access_key_id and aws_secret_access_key:

                session = boto3.Session(
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key, )

                return session

            elif role_arn and session_name:
                session = self._get_refreshable_session()
                return session

            else:
                raise AuthenticationException("Invalid session arguments")

        except Exception as e:
            raise AuthenticationException(e)

    def _get_refreshable_session(self):
        """
        This function returns a refreshable session for a given role and a session name
        """

        session_credentials = RefreshableCredentials.create_from_metadata(
            metadata=self._refresh_credentials(),
            refresh_using=self._refresh_credentials,
            method='sts-assume-role')
        session = get_session()
        session._credentials = session_credentials
        auto_refresh_session = boto3.Session(botocore_session=session)
        return auto_refresh_session

    def _refresh_credentials(self):
        """
        This function returns a credential given a role and session _name
        This function is triggered as and when the credential expires through RefreshCredential Object
        Taking the region as default us-east-1 . This will not impact any region-specific query.
        This is more like a placeholder.

        However , this may cause issue in case of gov-cloud regions.In that case the region needs to be
        changed to gov-cloud region name
        """

        sts_client = boto3.client("sts", region_name="us-east-1")
        params = {
            "RoleArn": self.role_arn,
            "RoleSessionName": self.session_name,
            "DurationSeconds": 900,
        }
        response = sts_client.assume_role(**params).get("Credentials")
        credentials = {
            "access_key": response.get("AccessKeyId"),
            "secret_key": response.get("SecretAccessKey"),
            "token": response.get("SessionToken"),
            "expiry_time": response.get("Expiration").isoformat(),

        }
        return credentials
