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
"""Validation helpers for Mandiant API endpoints."""


def validate_endpoint_path(endpoint: str) -> None:
    """Reject path-normalization segments before dispatching an API request."""
    path = endpoint.split("?", 1)[0].split("#", 1)[0]
    if any(segment in {".", ".."} for segment in path.split("/")):
        raise ValueError("Mandiant API endpoint contains a dot path segment")
