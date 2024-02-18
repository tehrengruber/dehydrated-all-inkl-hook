import zeep
import lxml
import json

type_attr = "{http://www.w3.org/2001/XMLSchema-instance}type"
nil_attr = '{http://www.w3.org/2001/XMLSchema-instance}nil'


def parse_result(inp):
    if isinstance(inp, list): # this just happens at the very top of the tree
        return {parse_result(el[0]): parse_result(el[1]) for el in inp}

    assert isinstance(inp, lxml.etree._Element)
    if type_attr in inp.attrib:
        type_ = inp.attrib[type_attr]
        if type_ == "xsd:string":
            return inp.text
        elif type_ == "xsd:float":
            return float(inp.text)
        elif type_ == "xsd:int":
            return int(inp.text)
        elif type_ == "ns2:Map":
            return {parse_result(el[0]): parse_result(el[1]) for el in inp}
        elif type_ == "SOAP-ENC:Array":
            return [parse_result(el) for el in inp]
        else:
            raise ValueError(f"Unsupported type {type_}")
    elif nil_attr in inp.attrib and inp.attrib[nil_attr] == "true":
        return None

    return lxml.etree.tostring(inp)


class KASAPI:
    username: str
    credential_token: str
    soap_request: zeep.Client

    def __init__(self, username, password):
        params = {
            'kas_login': username,
            'kas_auth_type': 'plain',
            'kas_auth_data': password,
            'session_lifetime': 600,  # validity of the token in seconds
            'session_update_lifetime': 'Y',  # update session on every request
            # 'session_2fa': 123456             # optional: if activated, otp for 2fa
        }

        soap_login = zeep.Client('./KasAuth.wsdl')

        self.username = username
        self.credential_token = soap_login.service.KasAuth(json.dumps(params))
        self.soap_request = zeep.Client('./KasApi.wsdl')

    def __getattr__(self, action):
        def request(**kwargs):
            raw_result = self.soap_request.service.KasApi(json.dumps({
                'kas_login': self.username,  # KAS user
                'kas_auth_type': 'session',  # auth per session token
                'kas_auth_data': self.credential_token,  # the auth token itself
                'kas_action': action,  # api function
                'KasRequestParams': kwargs
            }))
            parsed_result = parse_result(raw_result)
            assert parsed_result["Response"]["ReturnString"] == "TRUE"
            return parsed_result["Response"]["ReturnInfo"]
        return request
