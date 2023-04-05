#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Mandiant Advantage Threat Intelligence Connector for Splunk SOAR
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import datetime
import json
import time

import phantom.app as phantom
# Usage of the consts file is recommended
# from mandiantthreatintelligence_consts import *
import requests
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class MandiantThreatIntelligenceConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(MandiantThreatIntelligenceConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})
        if response.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        response.raise_for_status()

        try:
            html_text = response.text
        except:
            html_text = "Cannot parse HTML"

        return RetVal(phantom.APP_SUCCESS, html_text)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", headers={}, **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = config.get('base_url') + endpoint

        try:
            headers['Authorization'] = f'Bearer {self._state["bearer_token"]}'
            headers['X-App-Name'] = 'MA-Splunk-SOAR-for-Intel-v1.0.0'
            r = request_func(
                url,
                verify=config.get('verify_server_cert', True),
                headers=headers,
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param, action_result):
        """
        Test connectivity to Mandiant TI
        :param param: Phantom command parameters (empty)
        :param action_result: ActionResult returned by _get_bearer_token
        """

        self.save_progress("Connecting to endpoint")
        test_headers = {
            "Accept": "application/json"
        }
        ret_val, response = self._make_rest_call(
            'v4/entitlements', action_result, params=None, headers=test_headers
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            if response is not None:
                self.save_progress(response.text)
            return action_result.set_status(phantom.APP_ERROR, "Failed to access API")

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_indicator_lookup(self, param, action_result):
        """
        Retrieve information about an Indicator from Mandiant TI
        :param param: Phantom command parameters
        :param action_result: ActionResult returned by _get_bearer_token
        """
        self.save_progress("Connecting to endpoint")

        headers = {
            "Accept": "application/json"
        }
        data = {
            "requests": [
                {
                    "values": [
                        param.get("indicator")
                    ]
                }
            ]
        }

        ret_val, response = self._make_rest_call(
            'v4/indicator', action_result, headers=headers, json=data, method="post", params={"include_campaigns": True}
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Error getting indicator info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting indicator info")

        indicator = response['indicators'][0]
        ret_val, response = self._make_rest_call(
            f'v4/indicator/{indicator["type"]}/{indicator["value"]}', action_result, headers=headers, method="get",
            params={"include_campaigns": True}
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Error getting indicator info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting indicator info")

        self.save_progress("Retrieved indicator information")

        indicator = response
        categories = set()
        for source in indicator["sources"]:
            for category in source["category"]:
                categories.add(category)

        report_ret_val, report_response = self._make_rest_call(
            f'v4/indicator/{indicator["id"]}/reports', action_result, headers=headers, method="get",
            params={"include_campaigns": True}
        )

        if phantom.is_fail(report_ret_val):
            self.save_progress("Error getting indicator report info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting indicator report info")

        output = {
            "value": indicator["value"],
            "type": indicator["type"],
            "confidence": indicator["mscore"],
            "categories": list(categories),
            "attributed_associations": [{"name": a["name"], "type": a["type"]} for a in
                                        indicator.get("attributed_associations", [])],
            "first_seen": indicator["first_seen"],
            "last_seen": indicator["last_seen"],
            "reports": report_response.get("reports", []),
            "campaigns": indicator["campaigns"]
        }
        if indicator["type"] == "md5":
            output["associated_md5"] = [h["value"] for h in indicator["associated_hashes"] if h["type"] == "md5"][0]
            output["associated_sha1"] = [h["value"] for h in indicator["associated_hashes"] if h["type"] == "sha1"][0]
            output["associated_sha256"] = [h["value"] for h in indicator["associated_hashes"] if h["type"] == "sha256"][
                0]

        action_result.add_data(output)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_threat_actor_lookup(self, param, action_result):
        """
        Retrieve information and reports for a given Threat Actor from Mandiant TI
        :param param: Phantom command parameters
        :param action_result: ActionResult returned by _get_bearer_token
        """
        self.save_progress("Connecting to endpoint")

        headers = {
            "Accept": "application/json"
        }

        ret_val, response = self._make_rest_call(
            f'v4/actor/{param.get("threat_actor")}', action_result, headers=headers, method="get"
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Error getting threat actor info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting threat actor info")

        self.save_progress("Retrieved threat actor information")

        output = response

        report_ret_val, report_response = self._make_rest_call(
            f'v4/actor/{param.get("threat_actor")}/reports', action_result, headers=headers, method="get"
        )

        if phantom.is_fail(report_ret_val):
            self.save_progress("Error getting threat actor report info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting threat actor report info")

        self.save_progress("Retrieved threat actor report information")

        campaign_ret_val, campaign_response = self._make_rest_call(
            f'v4/actor/{param.get("threat_actor")}/campaigns', action_result, headers=headers, method="get"
        )

        if phantom.is_fail(campaign_ret_val):
            self.save_progress("Error getting threat actor campaign info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting threat actor campaign info")

        self.save_progress("Retrieved threat actor campaign information")

        output['campaigns'] = campaign_response['campaigns']

        target_locations = []
        for target_location in output["locations"]["target"]:
            target_location["sub_region"] = target_location["sub-region"]
            target_locations.append(target_location)
        output["locations"]["target"] = target_locations
        output["reports"] = report_response.get("reports", [])

        action_result.add_data(output)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_vulnerability_lookup(self, param, action_result):
        """
        Retrieve information about a Vulnerability from Mandiant TI
        :param param: Phantom command parameters
        :param action_result: ActionResult returned by _get_bearer_token
        """
        self.save_progress("Connecting to endpoint")

        headers = {
            "Accept": "application/json"
        }

        ret_val, response = self._make_rest_call(
            f'v4/vulnerability/{param.get("vulnerability")}', action_result, headers=headers, method="get"
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Error getting vulnerability info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting vulnerability info")

        self.save_progress("Retrieved vulnerability information")

        output = response
        output["risk_rating"] = output["risk_rating"].capitalize()

        action_result.add_data(output)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_malware_family_lookup(self, param, action_result):
        """
        Retrieve information and reports for a Malware Family from Mandiant TI
        :param param: Phantom command parameters
        :param action_result: ActionResult returned by _get_bearer_token
        """
        self.save_progress("Connecting to endpoint")

        headers = {
            "Accept": "application/json"
        }

        ret_val, response = self._make_rest_call(
            f'v4/malware/{param.get("malware_family")}', action_result, headers=headers, method="get"
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Error getting malware family info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting malware family info")

        self.save_progress("Retrieved malware family information")

        output = response

        report_ret_val, report_response = self._make_rest_call(
            f'v4/malware/{param.get("malware_family")}/reports', action_result, headers=headers, method="get"
        )

        if phantom.is_fail(report_ret_val):
            self.save_progress("Error getting malware family report info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting malware family report info")

        self.save_progress("Retrieved malware family report information")

        campaign_ret_val, campaign_response = self._make_rest_call(
            f'v4/malware/{param.get("malware_family")}/campaigns', action_result, headers=headers, method="get"
        )

        if phantom.is_fail(campaign_ret_val):
            self.save_progress("Error getting malware family campaign info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting malware family campaign info")

        self.save_progress("Retrieved malware family campaign information")

        output['campaigns'] = campaign_response['campaigns']

        output["reports"] = report_response.get("reports", [])

        action_result.add_data(output)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_search_mandiant(self, param, action_result):
        """
        Search Mandiant TI for a given string
        :param param: Phantom command parameters
        :param action_result: ActionResult returned by _get_bearer_token
        """
        self.save_progress("Connecting to endpoint")

        headers = {
            "Accept": "application/json"
        }

        data = {
            "search": param.get("query")
        }

        ret_val, response = self._make_rest_call(
            'v4/search', action_result, headers=headers, method="post", json=data
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Error performing search")
            return action_result.set_status(phantom.APP_ERROR, "Error performing search")

        output = {"objects": response["objects"]}

        while True:
            if len(response["objects"]) != 50:
                break

            data["next"] = response["next"]
            ret_val, response = self._make_rest_call(
                'v4/search', action_result, headers=headers, method="post", json=data
            )
            if phantom.is_fail(ret_val):
                self.save_progress("Error performing search")
                return action_result.set_status(phantom.APP_ERROR, "Error performing search")
            output["objects"].extend(response["objects"])

        self.save_progress("Search performed successfully")

        action_result.add_data(output)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_report_lookup(self, param, action_result):
        """
        Retrieve a single report, in HTML format, from Mandiant TI
        :param param: Phantom command parameters
        :param action_result: ActionResult returned by _get_bearer_token
        """
        self.save_progress("Connecting to endpoint")

        headers = {
            "Accept": "text/html"
        }

        ret_val, response = self._make_rest_call(
            f'v4/report/{param.get("report_id")}', action_result, headers=headers, method="get"
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Error getting report")
            return action_result.set_status(phantom.APP_ERROR, f"Error getting report: {ret_val} {response}")

        self.save_progress("Report retrieved successfully")

        output = {'report_id': param.get('report_id'),
                  'report': response}
        action_result.add_data(output)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_report_list(self, param, action_result: ActionResult):
        """
        Retrieve a list of reports from Mandiant TI and optionally filters by report_type
        :param param: Phantom command parameters
        :param action_result: ActionResult returned by _get_bearer_token
        """
        self.save_progress("Connecting to endpoint")

        headers = {
            "Accept": "application/json"
        }

        current_time = datetime.datetime.now()
        query = {
            'start_epoch': int((current_time - datetime.timedelta(days=int(param.get("days", 7)))).timestamp())
        }

        ret_val, response = self._make_rest_call(
            'v4/reports', action_result, headers=headers, params=query, method="get"
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Error getting reports")
            return action_result.set_status(phantom.APP_ERROR, "Error getting reports")

        output = {"objects": response["objects"]}
        while True:
            if len(response["objects"]) != 10:
                break

            query = {"next": response["next"]}

            ret_val, response = self._make_rest_call(
                'v4/reports', action_result, headers=headers, params=query, method="get"
            )

            if phantom.is_fail(ret_val):
                self.save_progress("Error getting reports")
                return action_result.set_status(phantom.APP_ERROR, "Error getting reports")

            output["objects"].extend(response["objects"])

        self.save_progress("Report retrieved successfully")

        if param.get("report_type") and param.get("report_type") != "":
            new_output = list(
                filter(lambda r: param.get("report_type").upper() == r["report_type"].upper(), output["objects"]))
            output['objects'] = new_output

        action_result.add_data(output)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_campaign_lookup(self, param, action_result):
        """
        Retrieve information and reports for a Malware Family from Mandiant TI
        :param param: Phantom command parameters
        :param action_result: ActionResult returned by _get_bearer_token
        """
        self.save_progress("Connecting to endpoint")

        headers = {
            "Accept": "application/json"
        }

        ret_val, response = self._make_rest_call(
            f'v4/campaign/{param.get("campaign")}', action_result, headers=headers, method="get"
        )
        if phantom.is_fail(ret_val):
            self.save_progress("Error getting campaign info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting campaign info")

        self.save_progress("Retrieved campaign information")

        output = response

        report_ret_val, report_response = self._make_rest_call(
            f'v4/campaign/{param.get("campaign")}/reports', action_result, headers=headers, method="get"
        )

        if phantom.is_fail(report_ret_val):
            self.save_progress("Error getting campaign report info")
            return action_result.set_status(phantom.APP_ERROR, "Error getting campaign report info")

        self.save_progress("Retrieved campaign report information")

        output["reports"] = report_response.get("reports", [])

        action_result.add_data(output)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_bearer_token(self, param):
        """
        Checks the expiration time of the bearer token (if present), and retrieves a new token if necessary
        :param param: Phantom command parameters
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        current_time = int(time.time())

        token_expired = (self._state.get("bearer_token") is None) or (
                self._state.get("bearer_token_expiration") <= current_time)

        if token_expired:
            config = self.get_config()
            auth = (config.get("api_key"), config.get("secret_key"))
            headers = {
                "Accept": "application/json"
            }
            data = {
                "grant_type": "client_credentials",
                "scope": ""
            }
            ret_val, response = self._make_rest_call('token', action_result, headers=headers, data=data, auth=auth,
                                                     method="post")

            if phantom.is_fail(ret_val):
                self.save_progress("Error getting new Bearer Token")
                return action_result

            self._state['bearer_token'] = response['access_token']
            self._state['bearer_token_expiration'] = current_time + response['expires_in']

            self.save_progress("Token retrieved successfully")
            return action_result

        self.save_progress("Token still valid; Using current token")
        return action_result

    def handle_action(self, param):
        ret_val = phantom.APP_ERROR

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        token_status = self._get_bearer_token(param)
        if not token_status:
            return ret_val

        function_map = {
            'test_connectivity': self._handle_test_connectivity,
            'indicator_lookup': self._handle_indicator_lookup,
            'campaign_lookup': self._handle_campaign_lookup,
            'threat_actor_lookup': self._handle_threat_actor_lookup,
            'vulnerability_lookup': self._handle_vulnerability_lookup,
            'malware_family_lookup': self._handle_malware_family_lookup,
            'report_lookup': self._handle_report_lookup,
            'report_list': self._handle_report_list,
            'search_mandiant': self._handle_search_mandiant
        }

        ret_val = function_map[action_id](param, token_status)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = MandiantThreatIntelligenceConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = MandiantThreatIntelligenceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector.handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
