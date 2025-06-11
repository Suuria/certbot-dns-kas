import unittest
from unittest.mock import Mock, patch

import pytest
from certbot import errors
from certbot_dns_kas.dns_kas import Authenticator, _KASClient


class TestKASAuthenticator(unittest.TestCase):
    
    def setUp(self):
        self.config = Mock()
        self.auth = Authenticator(self.config, "dns-kas")
    
    def test_more_info(self):
        info = self.auth.more_info()
        self.assertIn("All-inkl KAS API", info)
    
    @patch('certbot_dns_kas.dns_kas._KASClient')
    def test_perform(self, mock_client_class):
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        
        self.auth.credentials = Mock()
        self.auth.credentials.conf.return_value = "test_value"
        
        self.auth._perform("example.com", "_acme-challenge.example.com", "test_validation")
        
        mock_client.add_txt_record.assert_called_once_with(
            "_acme-challenge.example.com", "test_validation"
        )


class TestKASClient(unittest.TestCase):
    
    def setUp(self):
        with patch.object(_KASClient, '_initialize_api_urls'):
            self.client = _KASClient("test_login", "plain", "test_password")
            self.client.kas_api_url = "https://test.api.url"
            self.client.kas_auth_url = "https://test.auth.url"
    
    def test_initialization(self):
        self.assertEqual(self.client.login, "test_login")
        self.assertEqual(self.client.authtype, "plain")
        self.assertEqual(self.client.authdata, "test_password")
    
    @patch('requests.post')
    def test_get_credential_token_success(self, mock_post):
        mock_response = Mock()
        mock_response.text = '<return>test_token_12345</return>'
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        self.client._get_credential_token()
        
        self.assertEqual(self.client.credential_token, "test_token_12345")
    
    @patch('requests.post')
    def test_get_credential_token_failure(self, mock_post):
        mock_response = Mock()
        mock_response.text = '<SOAP-ENV:Fault><faultstring>Invalid credentials</faultstring></SOAP-ENV:Fault>'
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        with self.assertRaises(errors.PluginError):
            self.client._get_credential_token()
    
    def test_dict_to_kas_params(self):
        params = {
            "simple": "value",
            "nested": {"key1": "value1", "key2": "value2"}
        }
        result = self.client._dict_to_kas_params(params)
        
        self.assertIn('"simple":"value"', result)
        self.assertIn('"nested":', result)
        self.assertIn('"key1":"value1"', result)
    
    def test_is_soap_fault(self):
        fault_response = '<SOAP-ENV:Fault><faultstring>Error</faultstring></SOAP-ENV:Fault>'
        success_response = '<response>Success</response>'
        
        self.assertTrue(self.client._is_soap_fault(fault_response))
        self.assertFalse(self.client._is_soap_fault(success_response))


if __name__ == '__main__':
    unittest.main()