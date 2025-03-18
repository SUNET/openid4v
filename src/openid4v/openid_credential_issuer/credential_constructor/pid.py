import base64
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Union

from idpyoidc.message import Message
from idpysdjwt.issuer import Issuer
from openid4v.openid_credential_issuer.credential import CredentialConstructor
from satosa_idpyop.persistence import Persistence
from satosa_idpyop.utils import combine_client_subject_id

logger = logging.getLogger(__name__)
vctm_dict = {
    "vct": "urn:eu.europa.ec.eudi:pid:1",
    "name": "PID",
    "description": "This is an PID document issued by the well know PID issuer",
    "display": [
        {
            "lang": "en-US",
            "name": "PID",
            "rendering": {
                "simple": {
                    "logo": {
                        "uri": "",
                        "uri#integrity": "",
                        "alt_text": "PID Card",
                    },
                    "background_color": "",
                    "text_color": "",
                },
                "svg_templates": [
                    {
                        "uri": "https://raw.githubusercontent.com/AniaAlex/images/refs/heads/main/template-pid.svg",
                        "uri#integrity": "",
                        "properties": {
                            "orientation": "",
                            "color_scheme": "",
                            "contrast": "",
                        },
                    }
                ],
            },
        }
    ],
    "claims": [
        {
            "path": ["given_name"],
            "display": [
                {
                    "lang": "en-US",
                    "label": "Given Name",
                    "description": "Given Name",
                }
            ],
            "sd": "",
            "svg_id": "given_name",
        },
        {
            "path": ["family_name"],
            "display": [
                {
                    "lang": "en-US",
                    "label": "Last Name",
                    "description": "Last Name",
                }
            ],
            "sd": "",
            "svg_id": "family_name",
        },
        {
            "path": ["issuance_date"],
            "display": [
                {
                    "lang": "en-US",
                    "label": "Expiry Date",
                    "description": "The date and time expired this pid",
                }
            ],
            "sd": "",
            "svg_id": "issuance_date",
        },
        {
            "path": ["expiry_date"],
            "display": [
                {
                    "lang": "en-US",
                    "label": "Expiry Date",
                    "description": "The date and time expired this pid",
                }
            ],
            "sd": "",
            "svg_id": "expiry_date",
        },
    ],
    "schema_url": "",
    "schema_url#integrity": "",
    "extends": "",
    "extends#integrity": "",
}


def calculate_age(born_date: datetime) -> int:
    current_date = datetime.now()

    age = current_date.year - born_date.year
    if born_date.month > current_date.month:
        age -= 1
    elif born_date.month == current_date.month and born_date.day > current_date.day:
        age -= 1

    return age


def convert_to_date(date_string: str) -> datetime:
    try:
        return datetime.strptime(date_string, "%Y-%m-%d")
    except ValueError:
        return "Invalid date format. Use YYYY-MM-DD."


def is_over_18(date_string: str) -> bool:
    born_date = convert_to_date(date_string)
    return calculate_age(born_date) >= 18


def get_vctm(vctm=vctm_dict):
    json_string = json.dumps(vctm, separators=(",", ":"))
    base64_encoded = base64.urlsafe_b64encode(json_string.encode()).decode()
    return base64_encoded


class PIDConstructor(CredentialConstructor):

    def __init__(self, upstream_get, **kwargs):

        CredentialConstructor.__init__(self, upstream_get=upstream_get)
        self.url = kwargs.get("url")  # MUST have a value
        self.body = kwargs.get("body", {})
        self.claims = kwargs.get(
            "attributes", ["family_name", "given_name", "birth_date"]
        )

    def _get_userinfo(self, cntx, user_id, claims_restriction, client_id):
        _persistence = self.upstream_get("attribute", "persistence")
        logger.debug(f"Using {_persistence.name} persistence layer")
        client_subject_id = combine_client_subject_id(client_id, user_id)
        authn_claims = _persistence.load_claims(client_subject_id)
        # filter on accepted claims
        _ava = {}
        if {"family_name", "given_name", "birth_date"}.issubset(
            set(list(authn_claims.keys()))
        ):
            for attr, value in authn_claims.items():
                if attr in ["family_name", "given_name", "birth_date"]:
                    _ava[attr] = value

        logger.debug(f"Authentication claims: {_ava}")
        return _ava

    def __call__(
        self,
        user_id: str,
        client_id: str,
        request: Union[dict, Message],
        grant: Optional[dict] = None,
        id_token: Optional[str] = None,
        authz_detail: Optional[dict] = None,
        persistence: Optional[Persistence] = None,
    ) -> str:
        logger.debug(":" * 20 + "PID constructor" + ":" * 20)

        # Get extra arguments from the authorization request if available
        if "issuer_state" in grant.authorization_request:
            msg = Message().from_urlencoded(grant.authorization_request["issuer_state"])
            _body = msg.to_dict()
            _body["credential_type"] = "sdjwt"
            _vct = authz_detail["vct"]
            _body["document_type"] = _vct
        else:
            _body = grant.authorization_request

        logger.debug(f"Authorization request claims: {_body}")

        # and more arguments from what the authentication returned
        # _persistence = self.upstream_get("attribute", "persistence")
        logger.debug(f"Using {persistence.name} persistence layer")
        client_subject_id = combine_client_subject_id(client_id, user_id)
        authn_claims = persistence.load_claims(client_subject_id)
        logger.debug(f"Anna {authn_claims}")
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
            _body["identity"] = {"schema": {"name": "DefaultSchema"}}

        _body.update(_ava)

        # TODO: age_over_18 is OPTIONAL:the plan to implement in May 2025
        # TODO: FIX upon implementation there is a problmen in json
        # meaning false values will be ommited
        if "age_over_18" not in _body:
            pass
            # _body["age_over_18"]=is_over_18(_ava["birth_date"])
        # MANDATORY: hardcoded
        if "issuing_authority" not in _body:
            _body["issuing_authority"] = "EU"
        # MANDATORY: hardcoded
        if "issuing_country" not in _body:
            _body["issuing_country"] = "EU"
        if "vct" not in _body:
            _body["vct"] = "urn:eu.europa.ec.eudi:pid:1"
        # MANDATORY: hardcoded
        if "nationality" not in _body:
            _body["nationality"] = ["EU"]
        # MANDATORY: hardcoded
        if "birth_place" not in _body:
            _body["birth_place"] = "EU"

        if "issuance_date" not in _body:
            _body["issuance_date"] = datetime.today().strftime("%Y-%m-%d")
        # MANDATORY: hardcoded : admin expiry, not technical
        if "expiry_date" not in _body:
            _body["expiry_date"] = (datetime.today() + timedelta(days=365)).strftime(
                "%Y-%m-%d"
            )

        # TODO: Need to be fixed in the future with the wallet public key.
        # TODO: See "Representation of an Asymmetric Proof-of-Possession Key".
        # The commented line below retrieves wallet public keys saved in `op_storage`.
        # The corresponding private keys were not found.
        # The new flow works with Satosa's own keys instead.
        # _body["jwk"] = request["__verified_proof"].jws_header["jwk"]

        ci = Issuer(
            key_jar=self.upstream_get("attribute", "keyjar"),
            iss=self.upstream_get("attribute", "entity_id"),
            sign_alg="ES256",
            lifetime=31536000,
            holder_key=self.upstream_get("attribute", "keyjar").get_signing_key(
                key_type="EC"
            )[0],
        )

        logger.debug(f"Combined body: {_body}")
        vctm = get_vctm()
        _sdjwt = ci.create_holder_message(
            payload=_body, jws_headers={"vctm": [vctm], "typ": "example+sd-jwt"}
        )

        return json.dumps({"credentials": [{"credential": _sdjwt}]})


"""
import json
import logging
from typing import Optional, Union

from cryptojwt.jwk.jwk import key_from_jwk_dict
from idpyoidc.client.exception import OidcServiceError
from idpyoidc.exception import RequestError
from idpyoidc.message import Message
from satosa_idpyop.persistence import Persistence
from satosa_idpyop.utils import combine_client_subject_id

from openid4v.openid_credential_issuer.credential import CredentialConstructor

logger = logging.getLogger(__name__)


class PIDConstructor(CredentialConstructor):

    def __init__(self, upstream_get, **kwargs):
        CredentialConstructor.__init__(self, upstream_get=upstream_get)
        self.url = kwargs.get("url")  # MUST have a value
        self.body = kwargs.get("body", {})
        self.claims = kwargs.get(
            "attributes", ["family_name", "given_name", "birth_date"]
        )

    def _get_userinfo(self, cntx, user_id, claims_restriction, client_id):
        _persistence = self.upstream_get("attribute", "persistence")
        logger.debug(f"Using {_persistence.name} persistence layer")
        client_subject_id = combine_client_subject_id(client_id, user_id)
        authn_claims = _persistence.load_claims(client_subject_id)
        # filter on accepted claims
        _ava = {}
        if {"family_name", "given_name", "birth_date"}.issubset(
            set(list(authn_claims.keys()))
        ):
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
"""
