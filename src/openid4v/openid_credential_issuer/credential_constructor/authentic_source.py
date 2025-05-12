import json
import logging
from typing import Optional
from typing import Union

from cryptojwt.jwk.jwk import key_from_jwk_dict
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from satosa_idpyop.persistence import Persistence
from satosa_idpyop.utils import combine_client_subject_id

logger = logging.getLogger(__name__)

EXAMPLE = [
    {
        "credential_type": "sdjwt",
        "authentic_source": "EHIC:00001",
        "document_type": "EHIC",
        "collect_id": "collect_id_ehic_129",
        "authentic_source_person_id": "authentic_source_person_id_129",
        "family_name": "Wilson",
        "given_name": "Owen",
        "birth_date": "2007-09-11",
        "identity": {
            "schema": {
                "name": "DefaultSchema",
            }
        }
    },
    {
        "credential_type": "sdjwt",
        "authentic_source": "EHIC:00001",
        "document_type": "EHIC",
        "collect_id": "collect_id_ehic_88",
        "authentic_source_person_id": "authentic_source_person_id_88",
        "family_name": "Hopkins",
        "given_name": "Anthony",
        "birth_date": "2006-08-16",
        "identity": {
            "schema": {
                "name": "DefaultSchema",
            }
        }
    },
    {
        "credential_type": "sdjwt",
        "authentic_source": "PDA1:00001",
        "document_type": "PDA1",
        "collect_id": "collect_id_pda1_79",
        "authentic_source_person_id": "authentic_source_person_id_79",
        "family_name": "Foster",
        "given_name": "Jodie",
        "birth_date": "1991-10-30",
        "identity": {
            "schema": {
                "name": "DefaultSchema",
            }
        }
    }
]

OVERRIDE = True
BOOTSTRAP = False

def matches_example(body):
    keys = list(body.keys())
    if "identity" in keys:
        _val = body["identity"]
        keys.remove("identity")
        del body["identity"]
    else:
        _val = None
    for ex in EXAMPLE:
        _cmp = {k: v for k, v in ex.items() if k in keys}
        logger.debug(f"Compare: {body} vs {_cmp}")
        if body == _cmp:
            return ex
    if _val:
        body["identity"] = _val
    return None


def fetch_userinfo(body):
    ex = matches_example(body)
    if ex:
        body["identity"] = ex["identity"]
        _ava = {k: v for k, v in ex.items() if k in ["authentic_source_person_id", "family_name", "given_name",
                                                     "birth_date"]}
        body["identity"].update(_ava)

    return body


# Credential type : document_type
DOCTYPE = {
    "EHICCredential": "EHIC",
    "PDA1Credential": "PDA1",
    "DiplomaCredential": "Diploma",
    "ELM": "ELMCredential",
    "MicroCredential": "Microcredential",
    "PID": "PIDCredential",
}


class CredentialConstructor(object):

    def __init__(self, upstream_get, **kwargs):
        self.upstream_get = upstream_get
        self.url = kwargs.get("url")  # MUST have a value
        self.jwks_url = kwargs.get("jwks_url", "")
        self.body = kwargs.get("body")
        if not self.body:
            self.body = {k: v for k, v in EXAMPLE[0].items() if
                         k in ["authentic_source", "document_type", "credential_type"]}
        self.key = []
        self.jwks_uri = self.jwks_url or f"{self.url}/.well-known/jwks.json"
        logger.debug(f"jwks_uri: {self.jwks_uri}")
        self.fetch_jwks()

    def fetch_jwks(self):
        # fetch public key from the credential constructor
        # Format
        # {"issuer":"https://vc-interop-1.sunet.se",
        # "jwks":{
        #   "keys":[
        #       {"kid":"singing_",
        #        "crv":"P-256","kty":"EC","x":"jBdJcpK9LCxRvd7kQnhonSsN_fQ6q8fEhclThBRYAt4",
        #        "y":"8rVwmwcFy85bUZn3h00sMiAiFygnhBs0CRL5xFKsuXQ",
        #        "d":"3h0daeEviT8O_VMt0jA0bF-kecfnQcaT8yM6wjWJU78"}]}

        httpc = self.upstream_get("attribute", "httpc")
        httpc_params = self.upstream_get("attribute", "httpc_params")
        try:
            resp = httpc("GET", self.jwks_uri, **httpc_params)
        except Exception as err:
            logger.exception("fetch_jwks")
            raise err

        if resp.status_code != 200:
            logger.error(f"Jwks fetch from Credential Constructor at {self.jwks_uri} failed")
            # raise SystemError(f"Jwks fetch from Credential Constructor at {_jwks_uri} failed")
        else:
            _info = json.loads(resp.text)
            logger.debug(f"Fetched Credential Constructors keys: {_info}")
            # Two keys
            if "issuer" in _info and "jwks" in _info:
                self.key = []
                for key_spec in _info["jwks"]["keys"]:
                    _key = key_from_jwk_dict(key_spec)
                    if _key not in self.key:
                        self.key.append(_key)
                logger.debug(f"Credential Constructors keys: {[k.serialize() for k in self.key]}")
            else:
                raise ValueError("Missing jwks_info parameter")

    def get_response(
            self,
            url: str,
            method: Optional[str] = "POST",
            body: Optional[dict] = None,
            headers: Optional[dict] = None,
            **kwargs
    ):
        """

        :param url:
        :param method:
        :param body:
        :param response_body_type:
        :param headers:
        :param kwargs:
        :return:
        """
        httpc = self.upstream_get("attribute", "httpc")
        httpc_params = self.upstream_get("attribute", "httpc_params")
        try:
            logger.debug(f"{method} {url} {headers} {json.dumps(body)} {httpc_params}")
            resp = httpc(method, url, data=json.dumps(body), headers=headers, **httpc_params)
        except Exception as err:
            logger.error(f"Exception on request: {err}")
            raise RequestError(f"HTTP request failed {err}")

        if 400 <= resp.status_code:
            logger.error("Error response ({}): {}".format(resp.status_code, resp.text))
            raise OidcServiceError(f"HTTP ERROR: {resp.text} [{resp.status_code}] on {resp.url}")
        elif 300 <= resp.status_code < 400:
            return {"http_response": resp}
        else:
            return resp.text

    def _matching(self, body, persistence, client_id, user_id):
        # and more arguments from what the authentication returned
        # _persistence = self.upstream_get("attribute", "persistence")
        ex = matches_example(body)
        if ex:
            logger.debug(f"Will use example: {ex}")
            body["identity"] = ex["identity"]
            _ava = {k: v for k, v in ex.items() if k in ["authentic_source_person_id", "family_name", "given_name",
                                                         "birth_date"]}
            body["identity"].update(_ava)

        if persistence:
            logger.debug(f"Using {persistence.name} persistence layer")
            client_subject_id = combine_client_subject_id(client_id, user_id)
            authn_claims = persistence.load_claims(client_subject_id)
            # filter on accepted claims
            _ava = {}
            if {"family_name", "given_name", "birth_date"}.issubset(set(list(authn_claims.keys()))):
                for attr, value in authn_claims.items():
                    if attr in ["family_name", "given_name", "birth_date"]:
                        _ava[attr] = value
            else:
                for attr in ["family_name", "given_name", "birth_date"]:
                    _ava[attr] = EXAMPLE[0][attr]
            logger.debug(f"Authentication claims: {_ava}")

            if "identity" not in body:
                body["identity"] = EXAMPLE[0]["identity"]

            body["identity"].update(_ava)
        else:
            body = fetch_userinfo(body)
        return body

    def __call__(self,
                 user_id: str,
                 client_id: str,
                 request: Union[dict, Message],
                 grant: Optional[dict] = None,
                 id_token: Optional[str] = None,
                 authz_detail: Optional[dict] = None,
                 persistence: Optional[Persistence] = None,
                 ) -> str:
        logger.debug(":" * 20 + f"Credential constructor[authentic_source]" + ":" * 20)

        if not self.key:
            self.fetch_jwks()
            if not self.key:
                return json.dumps({"error": "failed to pick up keys"})

        # Get extra arguments from the authorization request if available
        if "issuer_state" in grant.authorization_request:
            msg = Message().from_urlencoded(grant.authorization_request["issuer_state"])
            _body = msg.to_dict()
            _body["credential_type"] = "sdjwt"
            _vct = authz_detail["vct"]
            if _vct in DOCTYPE:
                _vct = DOCTYPE[_vct]
            _body["document_type"] = _vct
        else:
            _body = grant.authorization_request

        logger.debug(f"Authorization request claims: {_body}")

        # and more arguments from what the authentication returned
        # _persistence = self.upstream_get("attribute", "persistence")
        if BOOTSTRAP:
            _body = self._matching(_body, persistence, client_id, user_id)
        else:
            logger.debug(f"Using {persistence.name} persistence layer")
            client_subject_id = combine_client_subject_id(client_id, user_id)
            authn_claims = persistence.load_claims(client_subject_id)
            # filter on accepted claims
            _ava = {}
            logger.debug(f"AVA claims: {authn_claims}")
            for attr, value in authn_claims.items():
                if attr in ["family_name", "given_name", "birth_date"]:
                    _ava[attr] = value
            logger.debug(f"Authentication claims: {_ava}")

            if "birth_date" in _ava:
                if isinstance(_ava["birth_date"], list):
                    _ava["birth_date"] = _ava["birth_date"][0]

            if "identity" not in _body:
                _body["identity"] = {
                    "schema": {
                        "name": "DefaultSchema"
                    }
                }

            _body["identity"].update(_ava)

        _body["jwk"] = request["__verified_proof"].jws_header["jwk"]
        # http://vc-interop-1.sunet.se/api/v1/credential
        logger.debug(f"Combined body: {_body}")
        msg = self.get_response(url=self.url, body=_body, headers={"Content-Type": "application/json"})
        logger.debug(f"return message: {msg}")
        return msg
