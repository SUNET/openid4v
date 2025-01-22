import json
import logging
from typing import Optional
from typing import Union

from cryptojwt.jwk.jwk import key_from_jwk_dict
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from openid4v.openid_credential_issuer.credential import CredentialConstructor
from satosa_idpyop.persistence import Persistence
from satosa_idpyop.utils import combine_client_subject_id

logger = logging.getLogger(__name__)


class PIDConstructor(CredentialConstructor):

    def __init__(self, upstream_get, **kwargs):
        CredentialConstructor.__init__(self, upstream_get=upstream_get)
        self.url = kwargs.get("url")  # MUST have a value
        self.body = kwargs.get("body", {})
        self.claims = kwargs.get("attributes", ["family_name", "given_name", "birth_date"])

    def _get_userinfo(self, cntx, user_id, claims_restriction, client_id):
        _persistence = self.upstream_get("attribute", "persistence")
        logger.debug(f"Using {_persistence.name} persistence layer")
        client_subject_id = combine_client_subject_id(client_id, user_id)
        authn_claims = _persistence.load_claims(client_subject_id)
        # filter on accepted claims
        _ava = {}
        if {"family_name", "given_name", "birth_date"}.issubset(set(list(authn_claims.keys()))):
            for attr, value in authn_claims.items():
                if attr in ["family_name", "given_name", "birth_date"]:
                    _ava[attr] = value

        logger.debug(f"Authentication claims: {_ava}")
        return _ava


    # def __call__(self,
    #              user_id: str,
    #              client_id: str,
    #              request: Union[dict, Message],
    #              grant: Optional[dict] = None,
    #              id_token: Optional[str] = None,
    #              authz_detail: Optional[dict] = None,
    #              persistence: Optional[Persistence] = None,
    #              ) -> str:
    #     logger.debug(":" * 20 + f"PID constructor" + ":" * 20)
    #
    #     # Get extra arguments from the authorization request if available
    #     if "issuer_state" in grant.authorization_request:
    #         msg = Message().from_urlencoded(grant.authorization_request["issuer_state"])
    #         _body = msg.to_dict()
    #         _body["credential_type"] = "sdjwt"
    #         _vct = authz_detail["vct"]
    #         # if _vct in DOCTYPE:
    #         #     _vct = DOCTYPE[_vct]
    #         _body["document_type"] = _vct
    #     else:
    #         _body = grant.authorization_request
    #
    #     logger.debug(f"Authorization request claims: {_body}")
    #
    #     # and more arguments from what the authentication returned
    #     # _persistence = self.upstream_get("attribute", "persistence")
    #     logger.debug(f"Using {persistence.name} persistence layer")
    #     client_subject_id = combine_client_subject_id(client_id, user_id)
    #     authn_claims = persistence.load_claims(client_subject_id)
    #     # filter on accepted claims
    #     _ava = {}
    #     logger.debug(f"AVA claims: {authn_claims}")
    #     for attr, value in authn_claims.items():
    #         if attr in ["family_name", "given_name", "birth_date"]:
    #             _ava[attr] = value
    #     logger.debug(f"Authentication claims: {_ava}")
    #
    #     if "birth_date" in _ava:
    #         if isinstance(_ava["birth_date"], list):
    #             _ava["birth_date"] = _ava["birth_date"][0]
    #
    #     if "identity" not in _body:
    #         _body["identity"] = {
    #             "schema": {
    #                 "name": "FR"
    #             }
    #         }
    #
    #     _body["identity"].update(_ava)
    #
    #     _body["jwk"] = request["__verified_proof"].jws_header["jwk"]
    #     # http://vc-interop-1.sunet.se/api/v1/credential
    #     logger.debug(f"Combined body: {_body}")
    #     msg = self.get_response(url=self.url, body=_body, headers={"Content-Type": "application/json"})
    #     logger.debug(f"return message: {msg}")
    #     return msg
