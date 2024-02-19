#!/usr/sbin/python3
import os
import sys
import time

import dns
import dns.exception
import dns.resolver

from dehydrated_all_inkl_hook.kas_api import KASAPI


def resolve_a_record(name):
	return dns.resolver.resolve(name, "A")[0].address


dns_servers = [resolve_a_record("ns5.kasserver.com"), resolve_a_record("ns6.kasserver.com")]


def _has_dns_propagated(name, token):
	try:
		if dns_servers:
			custom_resolver = dns.resolver.Resolver()
			custom_resolver.nameservers = dns_servers
			dns_response = custom_resolver.resolve(name, 'TXT')
		else:
			dns_response = dns.resolver.resolve(name, 'TXT')

		for rdata in dns_response:
			if token in [b.decode('utf-8') for b in rdata.strings]:
				return True

	except dns.exception.DNSException as e:
		print(" + {0}. Retrying query...".format(e))

	return False


def split_domain(domain):
	"""
	Split domain into subdomain and rest

	>>> split_domain("foo.bar.com")
	('foo', 'bar.com')

	>>> split_domain("bar.com")
	('', 'bar.com')
	"""
	parts = domain.split(".")
	assert len(parts)>=2
	*subdomain, domain, tld = parts
	return ".".join(subdomain), f"{domain}.{tld}"


def clean_challenge(kas_api: KASAPI, domain: str, _, token: str, **kwargs) -> None:
	try:
		subdomain, zone = split_domain(domain)
		print(f" + Removing TXT record: {domain} => {token}")

		name = f"_acme-challenge.{subdomain}"

		existing_records = kas_api.get_dns_settings(zone_host=zone)
		for entry in existing_records:
			if entry["record_name"] == name:
				if entry["record_data"] != token:
					raise ValueError("TXT record exists with different token.")
				record_id = entry["record_id"]
				kas_api.delete_dns_settings(record_id=record_id)
				print(f" + TXT record removed. (record_id: {record_id})")
				break
		else:
			print(f" + No TXT record found.")
	except Exception as e:
		print(f"Failed to clean challenge for {domain}: {str(e)}")
		sys.exit(1)


def deploy_challenge(kas_api: KASAPI, domain: str, challenge: str, token: str, **kwargs) -> None:
	try:
		subdomain, zone = split_domain(domain)
		print(f" + Creating TXT record: {domain} => {token}")
		print(f" + Challenge: {challenge}")
		print(f" + Zone: {zone}")

		if subdomain:
			name = f"_acme-challenge.{subdomain}"
		else:
			name = "_acme-challenge"

		existing_records = kas_api.get_dns_settings(zone_host=zone)
		for entry in existing_records:
			if entry["record_name"] == name:
				if entry["record_data"] != token:
					raise ValueError("TXT record already exists with different token.")
				print(" + TXT record exists, skipping creation.")
				return

		payload = {
			'zone_host': f"{zone}.",
			'record_type': 'TXT',
			'record_name': name,
			'record_data': token,
			'record_aux': '0'
		}
		result = kas_api.add_dns_settings(**payload)

		while not _has_dns_propagated(name+"."+zone, token):
			print(" + DNS not propagated, waiting 30s...")
			time.sleep(30)

		print(" + TXT record created.")
	except Exception as e:
		print(f"Failed to deploy challenge for {domain}: {str(e)}")
		sys.exit(1)


def main():
	# Init KAS API endpoint
	if "KAS_USERNAME" not in os.environ:
		raise ValueError("Environment variable KAS_USERNAME not set.")
	if "KAS_PASSWORD" not in os.environ:
		raise ValueError("Environment variable KAS_PASSWORD not set.")
	kas_username, kas_password = os.environ["KAS_USERNAME"], os.environ["KAS_PASSWORD"]

	kas_api = KASAPI(username=kas_username, password=kas_password)

	_, hook_action, *args = sys.argv
	if hook_action == "clean_challenge":
		clean_challenge(kas_api, *args)
	elif hook_action == "deploy_challenge":
		deploy_challenge(kas_api, *args)
	else:
		print(f"Invalid hook action: {hook_action}")


if __name__ == "__main__":
	main()
