# File: mandiantadvantagethreatintelligence_view.py
#
# Copyright (c) Mandiant, 2023-2025
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

# This file is responsible for any manipulation or parsing of data prior to rendering it as part of a widget


def get_ctx_result(result):
    ctx_result = {}
    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result["param"] = param

    if data:
        ctx_result["data"] = data

    if summary:
        ctx_result["summary"] = summary

    return ctx_result


def display_indicator(provides, all_app_runs, context):
    context["results"] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)

    return "mandiantthreatintelligence_view_indicator.html"


def display_campaign(provides, all_app_runs, context):
    context["results"] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)

    return "mandiantthreatintelligence_view_campaign.html"


def display_threat_actor(provides, all_app_runs, context):
    context["results"] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)
    return "mandiantthreatintelligence_view_threat_actor.html"


def display_vulnerability(provides, all_app_runs, context):
    context["results"] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)
    return "mandiantthreatintelligence_view_vulnerability.html"


def display_malware_family(provides, all_app_runs, context):
    context["results"] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)
    return "mandiantthreatintelligence_view_malware_family.html"


def display_report(provides, all_app_runs, context):
    context["results"] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)
    return "mandiantthreatintelligence_view_report.html"


def display_report_list(provides, all_app_runs, context):
    context["results"] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)
    return "mandiantthreatintelligence_view_report_list.html"


def display_search(provides, all_app_runs, context):
    context["results"] = results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            ctx_result = get_ctx_result(result)
            if not ctx_result:
                continue

            results.append(ctx_result)
    return "mandiantthreatintelligence_search.html"
