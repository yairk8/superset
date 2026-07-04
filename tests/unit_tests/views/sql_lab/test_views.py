# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from superset.views.sql_lab.views import ALLOWED_TAB_STATE_FIELDS


def test_allowed_tab_state_fields_excludes_sensitive_columns() -> None:
    sensitive_fields = {"id", "user_id"}
    assert not sensitive_fields & ALLOWED_TAB_STATE_FIELDS


def test_allowed_tab_state_fields_contains_expected_fields() -> None:
    expected = {
        "active",
        "autorun",
        "catalog",
        "database_id",
        "extra_json",
        "hide_left_bar",
        "label",
        "latest_query_id",
        "query_limit",
        "saved_query_id",
        "schema",
        "sql",
        "template_params",
    }
    assert ALLOWED_TAB_STATE_FIELDS == expected
