import unittest
from recursive_json_search import json_search
from test_data import key1, key2, data

class json_search_test(unittest.TestCase):
    '''Test module for testing the search function in recursive_json_search.py'''
    
    # ================= FUNC TESTS =================
    
    def test_search_found(self):
        '''Key should be found, return list should not be empty.'''
        # key1 la issueSummary, co chua trong data. Gia su goi bang role "admin" (hoac theo policy)
        self.assertTrue(len(json_search(key1, data, role="admin")) > 0)
        
    def test_search_not_found(self):
        '''Key should not be found, should return an empty list.'''
        self.assertEqual([], json_search(key2, data, role="admin"))
        
    def test_is_a_list(self):
        '''Should return a list.'''
        self.assertIsInstance(json_search(key1, data, role="admin"), list)


    # ================= SECURITY TESTS =================
    
    def test_security_viewer_cannot_read_apikey(self):
        '''Viewer should NOT be able to read apiKey.'''
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)
        
    def test_security_operator_cannot_read_apikey(self):
        '''Operator should NOT be able to read apiKey.'''
        result = json_search("apiKey", data, role="operator")
        self.assertEqual([], result)
        
    def test_security_viewer_cannot_read_management_ip(self):
        '''Viewer should NOT be able to read managementIpAddress.'''
        result = json_search("managementIpAddress", data, role="viewer")
        self.assertEqual([], result)
        
    def test_security_admin_can_read_apikey(self):
        '''Admin SHOULD be able to read apiKey.'''
        result = json_search("apiKey", data, role="admin")
        self.assertTrue(len(result) > 0)
        self.assertEqual(result[0]["apiKey"], "SNMP-COMMUNITY-STRING-7f3a9c")

if __name__ == '__main__':
    unittest.main()
