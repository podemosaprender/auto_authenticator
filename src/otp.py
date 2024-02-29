import base64
import json
import os
import sys
import urllib.parse as urlparse
from inspect import signature
import pyotp

import protobuf_generated_python.google_auth_pb2 as pb

verbose = os.environ.get('LOGLVL',0)

def main():
	otp_cfg = extract_otp_from_otp_url( os.environ.get('OTP_URL') )
	print(json.dumps(otp_cfg, indent=2))
	print(get_two_factor_code(otp_cfg))

#FROM: https://github.com/jan-janssen/pyauthenticator
def get_two_factor_code(otp_cfg):
	funct_sig = signature(pyotp.TOTP)
	if "digits" in otp_cfg:
		digits = int(otp_cfg["digits"])
	else:
		digits = funct_sig.parameters["digits"].default
	if "period" in otp_cfg:
		interval = int(otp_cfg["period"])
	else:
		interval = funct_sig.parameters["interval"].default
	if "issuer" in otp_cfg:
		issuer = otp_cfg["issuer"]
	else:
		issuer = funct_sig.parameters["issuer"].default
	return pyotp.TOTP(
		s=otp_cfg["secret"],
		digits=digits,
		issuer=issuer,
		interval=interval,
	).now()

#FROM: https://github.com/scito/extract_otp_secrets
def extract_otp_from_otp_url(otpauth_migration_url):
	payload = get_payload_from_otp_url(otpauth_migration_url)

	if not payload:
		return 0

	for raw_otp in payload.otp_parameters:
		secret = convert_secret_from_bytes_to_base32_str(raw_otp.secret)
		otp_type = get_otp_type_str_from_code(raw_otp.type)
		otp_url = build_otp_url(secret, raw_otp)
		otp = {
			"name": raw_otp.name,
			"secret": secret,
			"issuer": raw_otp.issuer,
			"type": otp_type,
			"counter": raw_otp.counter if raw_otp.type == 1 else None,
			"url": otp_url
		}

		return otp

def get_payload_from_otp_url(otp_url):
	'''Extracts the otp migration payload from an otp url. This function is the core of the this appliation.'''
	if not is_opt_url(otp_url):
		return None
	parsed_url = urlparse.urlparse(otp_url)
	if verbose > 0: log_debug(f"parsed_url={parsed_url}")
	try:
		params = urlparse.parse_qs(parsed_url.query, strict_parsing=True)
	except Exception:
		params = {}
	if verbose > 0: log_debug(f"querystring params={params}")
	if 'data' not in params:
		log_error(f"could not parse query parameter in input url\nurl: {otp_url}")
		return None
	data_base64 = params['data'][0]
	if verbose > 0: log_debug(f"data_base64={data_base64}")
	data_base64_fixed = data_base64.replace(' ', '+')
	if verbose > 0: log_debug(f"data_base64_fixed={data_base64_fixed}")
	data = base64.b64decode(data_base64_fixed, validate=True)
	payload = pb.MigrationPayload()
	try:
		payload.ParseFromString(data)
	except Exception as e:
		abort(f"Cannot decode otpauth-migration migration payload.\n"
			  f"data={data_base64}", e)
	if verbose > 0: log_debug(f"\nPayload Line", payload, sep='\n')

	return payload

def is_opt_url(otp_url) -> bool:
	if not otp_url.startswith('otpauth-migration://'):
		msg = f"input is not a otpauth-migration:// url\ninput: {otp_url}"
	return True

# https://stackoverflow.com/questions/40226049/find-enums-listed-in-python-descriptor-for-protobuf
def get_enum_name_by_number(parent, field_name) -> str:
	field_value = getattr(parent, field_name)
	return parent.DESCRIPTOR.fields_by_name[field_name].enum_type.values_by_number.get(field_value).name  # type: ignore # generic code

def get_otp_type_str_from_code(otp_type) -> str:
	return 'totp' if otp_type == 2 else 'hotp'

def convert_secret_from_bytes_to_base32_str(bytes) -> str:
	return str(base64.b32encode(bytes), 'utf-8').replace('=', '')

def build_otp_url(secret, raw_otp) -> str:
	url_params = {'secret': secret}
	if raw_otp.type == 1: url_params['counter'] = str(raw_otp.counter)
	if raw_otp.issuer: url_params['issuer'] = raw_otp.issuer
	otp_url = f"otpauth://{get_otp_type_str_from_code(raw_otp.type)}/{urlparse.quote(raw_otp.name)}?" + urlparse.urlencode(url_params)
	return otp_url

def log_debug(*values, sep= ' ') -> None:
	print(f"\nDEBUG: {str(values[0])}", *values[1:], sep)

def log_error(msg, exception= None) -> None:
	exception_text = "\nException: "
	eprint(f"\nERROR: {msg}{(exception_text + str(exception)) if exception else ''}")

def eprint(*values, **kwargs) -> None:
	print(*values, file=sys.stderr, **kwargs)

def abort(msg, exception= None) -> None:
	log_error(msg, exception)
	sys.exit(1)

if __name__ == '__main__':
	main()
