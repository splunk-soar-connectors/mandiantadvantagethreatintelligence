# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import unittest

from mandiantadvantagethreatintelligence_validation import validate_endpoint_path


class ValidateEndpointPathTests(unittest.TestCase):
    def test_accepts_normal_resource_paths(self):
        for endpoint in (
            "v4/indicator/ipv4/192.0.2.1",
            "v4/vulnerability/CVE-2026-1234",
            "v4/reports?limit=20",
        ):
            with self.subTest(endpoint=endpoint):
                validate_endpoint_path(endpoint)

    def test_rejects_exact_dot_segments(self):
        for endpoint in (
            "v4/indicator/./value",
            "v4/report/..",
            "v4/campaign/../users",
            "v4/report/./details?limit=1",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                validate_endpoint_path(endpoint)


if __name__ == "__main__":
    unittest.main()
