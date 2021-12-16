import unittest
import json
import os
import sys

from http_parser import match_value_list
from http_parser import process_entry


class TestHttpParser(unittest.TestCase):
    def setUp(self):
        har_file = open("test.har", 'r')
    	rule_file = open("test.rule", 'r')

    	har_data = json.load(har_file)
    	self.entries_list = har_data['log']['entries']
    	self.rule_data = json.load(rule_file)
    	url_rule_map = dict()

    def test_match_value_list(self):
        self.assertTrue(match_value_list(["test"], "test"))
        self.assertTrue(match_value_list(["test", "nomatch"], "test"))

        self.assertFalse(match_value_list(["nomatch"], "test"))

        self.assertTrue(match_value_list(["re:.*test"], "hello_test_world"))
        self.assertTrue(match_value_list(["re:.*test", "nomatch"], "hello_test_world"))

        self.assertFalse(match_value_list(["re:.*test", "nomatch"], "hello_round_world"))

    def test_process_entry(self):
        url_rule_map = dict()
    	for network_entry in self.entries_list:
    		process_entry(network_entry, self.rule_data, url_rule_map)

        self.assertTrue(len(url_rule_map) == 1)
        for url in url_rule_map:
            self.assertTrue(url_rule_map[url] == "rule_1")

if __name__ == '__main__':
    unittest.main()
