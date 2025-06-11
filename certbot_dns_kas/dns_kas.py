#!/usr/bin/env python3
"""
Certbot DNS authenticator plugin for All-inkl KAS Server
Based on the original shell script dns_kas.sh

Usage:
    certbot certonly \
        --authenticator dns-kas \
        --dns-kas-credentials /path/to/kas.ini \
        -d example.com

Credentials file format (kas.ini):
    dns_kas_login = your_login
    dns_kas_authtype = plain
    dns_kas_authdata = your_password
"""

import logging
import time
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

import requests
import zope.interface
from certbot import errors, interfaces
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for All-inkl KAS Server"""

    description = "Obtain certificates using a DNS TXT record (if you are using All-inkl KAS for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None
        self.kas_api_url = None
        self.kas_auth_url = None
        self.credential_token = None
        self.rate_limit = 5  # Default rate limit in seconds

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=60)
        add("credentials", help="KAS credentials INI file.")

    def more_info(self):
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            "the All-inkl KAS API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "KAS credentials INI file",
            {
                "login": "KAS login name",
                "authtype": "KAS auth type (default: plain)",
                "authdata": "KAS auth data (password)",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_kas_client().add_txt_record(validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_kas_client().del_txt_record(validation_name, validation)

    def _get_kas_client(self):
        return _KASClient(
            self.credentials.conf("login"),
            self.credentials.conf("authtype") or "plain",
            self.credentials.conf("authdata"),
        )


class _KASClient:
    """KAS API client for DNS operations"""

    def __init__(self, login: str, authtype: str, authdata: str):
        self.login = login
        self.authtype = authtype
        self.authdata = authdata
        self.credential_token = None
        self.rate_limit = 5
        
        # Initialize API URLs
        self._initialize_api_urls()

    def _initialize_api_urls(self):
        """Get API URLs from WSDL files"""
        try:
            # Get KAS API URL
            response = requests.get("https://kasapi.kasserver.com/soap/wsdl/KasApi.wsdl", timeout=30)
            response.raise_for_status()
            
            # Parse SOAP address location from WSDL
            root = ET.fromstring(response.text)
            # Find soap:address location attribute
            for elem in root.iter():
                if 'location' in elem.attrib and 'kasapi' in elem.attrib.get('location', '').lower():
                    self.kas_api_url = elem.attrib['location']
                    break
            
            if not self.kas_api_url:
                # Fallback URL
                self.kas_api_url = "https://kasapi.kasserver.com/soap/KasApi.php"
            
            # Get KAS Auth URL
            response = requests.get("https://kasapi.kasserver.com/soap/wsdl/KasAuth.wsdl", timeout=30)
            response.raise_for_status()
            
            root = ET.fromstring(response.text)
            for elem in root.iter():
                if 'location' in elem.attrib and 'kasapi' in elem.attrib.get('location', '').lower():
                    self.kas_auth_url = elem.attrib['location']
                    break
            
            if not self.kas_auth_url:
                # Fallback URL
                self.kas_auth_url = "https://kasapi.kasserver.com/soap/KasAuth.php"
                
            logger.info(f"[KAS] API URL: {self.kas_api_url}")
            logger.info(f"[KAS] Auth URL: {self.kas_auth_url}")
            
        except Exception as e:
            logger.warning(f"[KAS] Could not retrieve API URLs from WSDL: {e}")
            # Use fallback URLs
            self.kas_api_url = "https://kasapi.kasserver.com/soap/KasApi.php"
            self.kas_auth_url = "https://kasapi.kasserver.com/soap/KasAuth.php"

    def add_txt_record(self, record_name: str, record_value: str):
        """Add a TXT record"""
        logger.info(f"[KAS] Adding TXT record: {record_name}")
        
        # Get credential token
        self._get_credential_token()
        
        # Get zone and record name
        zone, clean_record_name = self._get_zone_and_record_name(record_name)
        
        # Check for existing records and delete them
        existing_record_ids = self._get_record_ids(zone, clean_record_name, record_value)
        if existing_record_ids:
            logger.info("[KAS] Existing records found. Deleting old entries")
            for record_id in existing_record_ids:
                self._delete_record_by_id(record_id)
        
        # Create new TXT record
        logger.info("[KAS] Creating TXT DNS record")
        params = {
            "record_name": clean_record_name,
            "record_type": "TXT",
            "record_data": record_value,
            "record_aux": "0",
            "zone_host": zone
        }
        
        response = self._call_api("add_dns_settings", params)
        self._check_response(response, "add")

    def del_txt_record(self, record_name: str, record_value: str):
        """Delete a TXT record"""
        logger.info(f"[KAS] Removing TXT record: {record_name}")
        
        # Get credential token
        self._get_credential_token()
        
        # Get zone and record name
        zone, clean_record_name = self._get_zone_and_record_name(record_name)
        
        # Get record IDs to delete
        record_ids = self._get_record_ids(zone, clean_record_name, record_value)
        
        if record_ids:
            logger.info(f"[KAS] Removing entries with IDs: {record_ids}")
            for record_id in record_ids:
                self._delete_record_by_id(record_id)
        else:
            logger.info("[KAS] No records found to delete")

    def _get_credential_token(self):
        """Retrieve authentication token"""
        logger.info("[KAS] Retrieving credential token")
        
        params = {
            "kas_login": self.login,
            "kas_auth_type": self.authtype,
            "kas_auth_data": self.authdata,
            "session_lifetime": 600,
            "session_update_lifetime": "Y"
        }
        
        data = self._build_soap_request("KasAuth", params, "urn:xmethodsKasApiAuthentication")
        
        time.sleep(self.rate_limit)  # Rate limiting
        
        headers = {
            "Content-Type": "text/xml",
            "SOAPAction": "urn:xmethodsKasApiAuthentication#KasAuth"
        }
        
        try:
            response = requests.post(self.kas_auth_url, data=data, headers=headers, timeout=30)
            response.raise_for_status()
        except requests.RequestException as e:
            raise errors.PluginError(f"[KAS] Authentication request failed: {e}")
        
        # Parse response to get token
        if self._is_soap_fault(response.text):
            fault = self._get_soap_fault_string(response.text)
            raise errors.PluginError(f"[KAS] Authentication failed: {fault}")
        
        # Extract token from response
        try:
            root = ET.fromstring(response.text)
            # Find the return element
            for elem in root.iter():
                if elem.text and len(elem.text) > 20:  # Token should be longer
                    self.credential_token = elem.text.strip()
                    break
        except ET.ParseError:
            # Fallback: regex-like extraction
            import re
            match = re.search(r'<return[^>]*>([^<]+)</return>', response.text)
            if match:
                self.credential_token = match.group(1).strip()
        
        if not self.credential_token:
            raise errors.PluginError("[KAS] Could not extract credential token from response")
        
        logger.debug(f"[KAS] Credential token obtained: {self.credential_token[:10]}...")

    def _get_zone_and_record_name(self, full_domain: str) -> tuple:
        """Get the zone and record name for a domain"""
        logger.info("[KAS] Checking zone and record name")
        
        response = self._call_api("get_domains")
        
        if self._is_soap_fault(response):
            fault = self._get_soap_fault_string(response)
            raise errors.PluginError(f"[KAS] Could not get domains: {fault}")
        
        # Extract domain names from response
        domains = self._extract_domains_from_response(response)
        
        # Find the best matching zone
        domain_clean = full_domain.rstrip('.')
        best_zone = None
        
        for domain in domains:
            if domain_clean.endswith(domain) and (not best_zone or len(domain) > len(best_zone)):
                best_zone = domain
        
        if not best_zone:
            raise errors.PluginError(f"[KAS] No matching zone found for {full_domain}")
        
        zone = best_zone + "."
        record_name = domain_clean.replace(f".{best_zone}", "").replace(best_zone, "")
        
        logger.debug(f"[KAS] Zone: {zone}, Record name: {record_name}")
        return zone, record_name

    def _get_record_ids(self, zone: str, record_name: str, record_value: str) -> List[str]:
        """Get record IDs for existing TXT records"""
        params = {"zone_host": zone}
        response = self._call_api("get_dns_settings", params)
        
        if self._is_soap_fault(response):
            fault = self._get_soap_fault_string(response)
            raise errors.PluginError(f"[KAS] Could not get DNS settings: {fault}")
        
        # Parse response to find matching records
        record_ids = []
        try:
            # Simple text parsing approach
            if record_name in response and "TXT" in response and record_value in response:
                import re

                # Look for record_id patterns
                pattern = r'<key[^>]*>record_id</key><value[^>]*>([^<]+)</value>'
                matches = re.findall(pattern, response)
                
                # This is a simplified approach - in a real implementation,
                # you'd want to properly parse the XML structure
                for match in matches:
                    if match.strip():
                        record_ids.append(match.strip())
        except Exception as e:
            logger.warning(f"[KAS] Error parsing record IDs: {e}")
        
        return record_ids

    def _delete_record_by_id(self, record_id: str):
        """Delete a DNS record by ID"""
        params = {"record_id": record_id}
        response = self._call_api("delete_dns_settings", params)
        self._check_response(response, "delete")

    def _call_api(self, action: str, params: Optional[Dict[str, Any]] = None) -> str:
        """Make an API call"""
        auth_params = {
            "kas_login": self.login,
            "kas_auth_type": "session",
            "kas_auth_data": self.credential_token,
            "kas_action": action
        }
        
        if params:
            auth_params["KasRequestParams"] = params
        
        data = self._build_soap_request("KasApi", auth_params, "urn:xmethodsKasApi")
        
        time.sleep(self.rate_limit)  # Rate limiting
        
        headers = {
            "Content-Type": "text/xml",
            "SOAPAction": "urn:xmethodsKasApi#KasApi"
        }
        
        try:
            response = requests.post(self.kas_api_url, data=data, headers=headers, timeout=30)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            raise errors.PluginError(f"[KAS] API request failed: {e}")

    def _build_soap_request(self, method: str, params: Dict[str, Any], namespace: str) -> str:
        """Build SOAP request XML"""
        # Convert params to JSON-like string format that KAS expects
        params_str = self._dict_to_kas_params(params)
        
        envelope = f'''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" 
                   xmlns:ns1="{namespace}" 
                   xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
                   xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" 
                   SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <SOAP-ENV:Body>
        <ns1:{method}>
            <Params xsi:type="xsd:string">{{{params_str}}}</Params>
        </ns1:{method}>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''
        
        return envelope

    def _dict_to_kas_params(self, params: Dict[str, Any]) -> str:
        """Convert dict to KAS parameter format"""
        param_parts = []
        for key, value in params.items():
            if isinstance(value, dict):
                # Handle nested parameters
                nested_parts = []
                for nested_key, nested_value in value.items():
                    nested_parts.append(f'"{nested_key}":"{nested_value}"')
                param_parts.append(f'"{key}":{{{",".join(nested_parts)}}}')
            else:
                param_parts.append(f'"{key}":"{value}"')
        
        return ",".join(param_parts)

    def _is_soap_fault(self, response: str) -> bool:
        """Check if response contains a SOAP fault"""
        return "<SOAP-ENV:Fault>" in response

    def _get_soap_fault_string(self, response: str) -> str:
        """Extract fault string from SOAP fault response"""
        try:
            import re
            match = re.search(r'<faultstring>([^<]+)</faultstring>', response)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "Unknown SOAP fault"

    def _extract_domains_from_response(self, response: str) -> List[str]:
        """Extract domain names from get_domains response"""
        domains = []
        try:
            import re

            # Look for domain_name values
            pattern = r'<key[^>]*>domain_name</key><value[^>]*>([^<]+)</value>'
            matches = re.findall(pattern, response)
            domains = [match.strip() for match in matches if match.strip()]
        except Exception as e:
            logger.warning(f"[KAS] Error parsing domains: {e}")
        
        return domains

    def _check_response(self, response: str, operation: str):
        """Check if the response indicates success"""
        if not response:
            raise errors.PluginError(f"[KAS] Empty response for {operation} operation")
        
        if self._is_soap_fault(response):
            fault = self._get_soap_fault_string(response)
            
            # Handle specific known errors
            if fault == "record_already_exists" and operation == "add":
                logger.info("[KAS] Record already exists, which may not be a problem")
                return
            elif fault == "record_id_not_found" and operation == "delete":
                logger.info("[KAS] Record not found for deletion, which may not be a problem")
                return
            else:
                raise errors.PluginError(f"[KAS] {operation.title()} operation failed: {fault}")
        
        # Check for success indicator
        if 'ReturnString</key><value xsi:type="xsd:string">TRUE</value>' not in response:
            raise errors.PluginError(f"[KAS] {operation.title()} operation may have failed - no success indicator found")


# Entry point for setuptools
def main():
    """Main entry point for the plugin"""
    pass


if __name__ == "__main__":
    main()
