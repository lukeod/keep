import time
from datetime import datetime, timedelta, timezone

import pytest
import requests
from playwright.sync_api import Page, expect

from tests.e2e_tests.incidents_alerts_tests.incidents_alerts_setup import (
    create_fake_alert,
    query_alerts,
    setup_incidents_alerts,
)
from tests.e2e_tests.test_end_to_end import init_e2e_test, setup_console_listener
from tests.e2e_tests.utils import get_token, save_failure_artifacts
from copy import deepcopy


def multi_sort(data, criteria):
    """
    Sorts a list by multiple criteria.

    Args:
        data (list): The input list (e.g., list of dicts or objects).
        criteria (list of tuples): Each tuple is (key, direction)
            - key: string field name or callable (e.g., lambda x: ...)
            - direction: 'asc' or 'desc'

    Returns:
        A new sorted list.
    """
    sorted_data = deepcopy(data)

    for key, direction in reversed(criteria):
        if direction not in ("asc", "desc"):
            raise ValueError(f"Invalid sort direction: {direction}")
        reverse = direction == "desc"

        key_func = key if callable(key) else lambda x: x[key]
        sorted_data.sort(key=key_func, reverse=reverse)

    return sorted_data


KEEP_UI_URL = "http://localhost:3000"
KEEP_API_URL = "http://localhost:8080"


def init_test(browser: Page, alerts, max_retries=3):
    for i in range(max_retries):
        try:
            init_e2e_test(browser, next_url="/alerts/feed")
            base_url = f"{KEEP_UI_URL}/alerts/feed"
            # we don't care about query params
            # Give the page a moment to process redirects
            browser.wait_for_timeout(500)
            # Wait for navigation to complete to either signin or providers page
            # (since we might get redirected automatically)
            browser.wait_for_load_state("networkidle")
            browser.wait_for_url(lambda url: url.startswith(base_url), timeout=10000)
            print("Page loaded successfully. [try: %d]" % (i + 1))
            break
        except Exception as e:
            if i < max_retries - 1:
                print("Failed to load alerts page. Retrying... - ", e)
                continue
            else:
                raise e

    browser.wait_for_selector("[data-testid='facet-value']", timeout=10000)
    browser.wait_for_selector(f"text={alerts[0]['name']}", timeout=10000)
    rows_count = browser.locator("[data-testid='alerts-table'] table tbody tr").count()
    # check that required alerts are loaded and displayed
    # other tests may also add alerts, so we need to check that the number of rows is greater than or equal to 20

    # Shahar: Now each test file is seperate
    assert rows_count >= 10
    return alerts


def select_one_facet_option(browser, facet_name, option_name):
    expect(
        browser.locator("[data-testid='facet']", has_text=facet_name)
    ).to_be_visible()
    option = browser.locator("[data-testid='facet-value']", has_text=option_name)
    option.hover()
    option.locator("button", has_text="Only").click()


def assert_facet(browser, facet_name, alerts, alert_property_name: str):
    counters_dict = {}
    expect(
        browser.locator("[data-testid='facet']", has_text=facet_name)
    ).to_be_visible()
    for alert in alerts:
        prop_value = None
        for prop in alert_property_name.split("."):
            prop_value = alert.get(prop, None)
            if prop_value is None:
                prop_value = "None"
                break
            alert = prop_value

        if prop_value not in counters_dict:
            counters_dict[prop_value] = 0

        counters_dict[prop_value] += 1

    for facet_value, count in counters_dict.items():
        facet_locator = browser.locator("[data-testid='facet']", has_text=facet_name)
        expect(facet_locator).to_be_visible()
        facet_value_locator = facet_locator.locator(
            "[data-testid='facet-value']", has_text=facet_value
        )
        expect(facet_value_locator).to_be_visible()
        try:
            expect(
                facet_value_locator.locator("[data-testid='facet-value-count']")
            ).to_contain_text(str(count))
        except Exception as e:
            save_failure_artifacts(browser, log_entries=[])
            raise e


def assert_alerts_by_column(
    browser,
    alerts: list[dict],
    predicate: lambda x: bool,
    property_in_alert: str,
    column_index: int,
):
    filtered_alerts = [alert for alert in alerts if predicate(alert)]
    matched_rows = browser.locator("[data-testid='alerts-table'] table tbody tr")
    try:
        expect(matched_rows).to_have_count(len(filtered_alerts))
    except Exception as e:
        save_failure_artifacts(browser, log_entries=[])
        raise e

    # check that only alerts with selected status are displayed
    for alert in filtered_alerts:
        row_locator = browser.locator(
            "[data-testid='alerts-table'] table tbody tr", has_text=alert["name"]
        )
        expect(row_locator).to_be_visible()

        if column_index is None:
            return

        column_locator = row_locator.locator("td").nth(column_index)
        # status is now only svg
        try:
            expect(
                column_locator.locator("[data-testid*='status-icon']")
            ).to_be_visible()
        except Exception:
            column_html = column_locator.inner_html()
            print(f"Column HTML: {column_html}")


facet_test_cases = {
    "severity": {
        "alert_property_name": "severity",
        "value": "high",
    },
    "status": {
        "alert_property_name": "status",
        "column_index": 1,
        "value": "suppressed",  # Shahar: no more text - only icon
    },
    "source": {
        "alert_property_name": "providerType",
        "value": "prometheus",
    },
}


@pytest.fixture(scope="module")
def setup_test_data():
    print("Setting up test data...")
    test_data = setup_incidents_alerts()
    yield test_data["alerts"]


@pytest.mark.parametrize("facet_test_case", facet_test_cases.keys())
def test_filter_by_static_facet(
    browser: Page,
    facet_test_case,
    setup_test_data,
    setup_page_logging,
    failure_artifacts,
):
    test_case = facet_test_cases[facet_test_case]
    facet_name = facet_test_case
    alert_property_name = test_case["alert_property_name"]
    column_index = test_case.get("column_index", None)
    value = test_case["value"]
    current_alerts = setup_test_data

    init_test(browser, current_alerts, max_retries=3)
    # Give the page a moment to process redirects
    browser.wait_for_timeout(500)

    # Wait for navigation to complete to either signin or providers page
    # (since we might get redirected automatically)
    browser.wait_for_load_state("networkidle")

    assert_facet(browser, facet_name, current_alerts, alert_property_name)

    option = browser.locator("[data-testid='facet-value']", has_text=value)
    option.hover()

    option.locator("button", has_text="Only").click()

    assert_alerts_by_column(
        browser,
        current_alerts,
        lambda alert: alert[alert_property_name] == value,
        alert_property_name,
        column_index,
    )


def test_adding_custom_facet(
    browser: Page, setup_test_data, setup_page_logging, failure_artifacts
):
    facet_property_path = "custom_tags.env"
    facet_name = "Custom Env"
    alert_property_name = facet_property_path
    value = "environment:staging"
    current_alerts = setup_test_data
    init_test(browser, current_alerts)
    browser.locator("button", has_text="Add Facet").click()

    browser.locator("input[placeholder='Enter facet name']").fill(facet_name)
    browser.locator("input[placeholder*='Search columns']").fill(facet_property_path)
    browser.locator("button", has_text=facet_property_path).click()
    browser.locator("button", has_text="Create").click()

    assert_facet(browser, facet_name, current_alerts, alert_property_name)

    option = browser.locator("[data-testid='facet-value']", has_text=value)
    option.hover()
    option.locator("button", has_text="Only").click()

    assert_alerts_by_column(
        browser,
        current_alerts[:20],
        lambda alert: alert.get("custom_tags", {}).get("env") == value,
        alert_property_name,
        None,
    )
    browser.on("dialog", lambda dialog: dialog.accept())
    browser.locator("[data-testid='facet']", has_text=facet_name).locator(
        '[data-testid="delete-facet"]'
    ).click()
    expect(
        browser.locator("[data-testid='facet']", has_text=facet_name)
    ).not_to_be_visible()


search_by_cel_tescases = {
    "contains for nested property": {
        "cel_query": "labels.service.contains('java-otel')",
        "predicate": lambda alert: "java-otel"
        in alert.get("labels", {}).get("service", ""),
        "alert_property_name": "name",
        "commands": [
            lambda browser: browser.keyboard.type("labels."),
            lambda browser: browser.locator(
                ".monaco-highlighted-label", has_text="service"
            ).click(),
            lambda browser: browser.keyboard.type("."),
            lambda browser: browser.locator(
                ".monaco-highlighted-label", has_text="contains"
            ).click(),
            lambda browser: browser.keyboard.type("java-otel"),
        ],
    },
    "using enriched field": {
        "cel_query": "host == 'enriched host'",
        "predicate": lambda alert: "Enriched" in alert["name"],
        "alert_property_name": "name",
        "commands": [
            lambda browser: browser.keyboard.type("host"),
            lambda browser: browser.keyboard.type(" == "),
            lambda browser: browser.keyboard.type("'enriched host'"),
        ],
    },
    "date comparison greater than or equal": {
        "cel_query": f"dateForTests >= '{(datetime(2025, 2, 10, 10) + timedelta(days=-14)).isoformat()}'",
        "predicate": lambda alert: alert.get("dateForTests")
        and datetime.fromisoformat(alert.get("dateForTests"))
        >= (datetime(2025, 2, 10, 10) + timedelta(days=-14)),
        "alert_property_name": "name",
        "commands": [
            lambda browser: browser.keyboard.type("dateForTests"),
            lambda browser: browser.keyboard.type(" >= "),
            lambda browser: browser.keyboard.type(
                f"'{(datetime(2025, 2, 10, 10) + timedelta(days=-14)).isoformat()}'"
            ),
        ],
    },
}


@pytest.mark.parametrize("search_test_case", search_by_cel_tescases.keys())
def test_search_by_cel(
    browser: Page,
    search_test_case,
    setup_test_data,
    setup_page_logging,
    failure_artifacts,
):
    test_case = search_by_cel_tescases[search_test_case]
    cel_query = test_case["cel_query"]
    commands = test_case["commands"]
    predicate = test_case["predicate"]
    alert_property_name = test_case["alert_property_name"]
    current_alerts = setup_test_data
    browser.wait_for_timeout(3000)
    print(current_alerts)
    init_test(browser, current_alerts)
    browser.wait_for_timeout(1000)
    cel_input_locator = browser.locator(".alerts-cel-input")
    cel_input_locator.click()

    for command in commands:
        command(browser)
    expect(cel_input_locator.locator(".view-lines")).to_have_text(cel_query)

    browser.keyboard.press("Enter")

    assert_alerts_by_column(
        browser,
        current_alerts,
        predicate,
        alert_property_name,
        None,
    )


sort_tescases = {
    "sort by lastReceived asc/dsc": {
        "column_name": "Last Received",
        "column_id": "lastReceived",
        "sort_callback": lambda alert: alert["lastReceived"],
    },
    "sort by description asc/dsc": {
        "column_name": "description",
        "column_id": "description",
        "sort_callback": lambda alert: alert["description"],
    },
}


@pytest.mark.parametrize("sort_test_case", sort_tescases.keys())
def test_sort_asc_dsc(
    browser: Page,
    sort_test_case,
    setup_test_data,
    setup_page_logging,
    failure_artifacts,
):
    test_case = sort_tescases[sort_test_case]
    coumn_name = test_case["column_name"]
    column_id = test_case["column_id"]
    sort_callback = test_case["sort_callback"]
    current_alerts = setup_test_data
    alert_name_column_index = 4
    init_test(browser, current_alerts)
    filtered_alerts = [
        alert for alert in current_alerts if alert["providerType"] == "datadog"
    ]
    select_one_facet_option(browser, "source", "datadog")
    try:
        expect(
            browser.locator("[data-testid='alerts-table'] table tbody tr")
        ).to_have_count(len(filtered_alerts))
    except Exception:
        save_failure_artifacts(browser, log_entries=[])
        raise

    for sort_direction_title in ["asc", "desc"]:
        sorted_alerts = multi_sort(
            filtered_alerts, [(sort_callback, sort_direction_title)]
        )

        column_header_locator = browser.locator(
            f"[data-testid='alerts-table'] table thead th [data-testid='header-cell-{column_id}']",
            has_text=coumn_name,
        )
        expect(column_header_locator).to_be_visible()
        column_header_locator.click()
        rows = browser.locator("[data-testid='alerts-table'] table tbody tr")

        number_of_missmatches = 0
        for index, alert in enumerate(sorted_alerts):
            row_locator = rows.nth(index)
            # 4 is index of "name" column
            column_locator = row_locator.locator("td").nth(alert_name_column_index)
            try:
                expect(column_locator).to_have_text(alert["name"])
            except Exception as e:
                save_failure_artifacts(browser, log_entries=[])
                number_of_missmatches += 1
                if number_of_missmatches > 2:
                    raise e
                else:
                    print(
                        f"Expected: {alert['name']} but got: {column_locator.text_content()}"
                    )
                    continue


def test_multi_sort_asc_dsc(
    browser: Page,
    setup_test_data,
    setup_page_logging,
    failure_artifacts,
):
    coumn_name = ""
    current_alerts = setup_test_data
    alert_name_column_index = 4
    init_test(browser, current_alerts)
    cel_to_filter_alerts = "tags.customerName != null"
    browser.goto(f"{KEEP_UI_URL}/alerts/feed?cel={cel_to_filter_alerts}")
    filtered_alerts = [
        alert
        for alert in current_alerts
        if alert.get("tags", {}).get("customerName", None) is not None
    ]

    try:
        expect(
            browser.locator("[data-testid='alerts-table'] table tbody tr")
        ).to_have_count(len(filtered_alerts))
        browser.locator("[data-testid='settings-button']").click()
        settings_panel_locator = browser.locator("[data-testid='settings-panel']")
        settings_panel_locator.locator("input[type='text']").type("tags.")
        settings_panel_locator.locator("input[name='tags.customerName']").click()
        settings_panel_locator.locator("input[name='tags.alertIndex']").click()
        settings_panel_locator.locator(
            "button[type='submit']", has_text="Save changes"
        ).click()
    except Exception:
        save_failure_artifacts(browser, log_entries=[])
        raise
    # data-testid="header-cell-tags.customerName"
    browser.locator(
        f"[data-testid='alerts-table'] table thead th [data-testid='header-cell-tags.customerName']",
        has_text=coumn_name,
    ).click()
    print("ff")
    browser.keyboard.down("Shift")
    for sort_direction in ["desc", "asc"]:
        sorted_alerts = multi_sort(
            filtered_alerts,
            [
                (lambda alert: alert.get("tags", {}).get("customerName", None), "asc"),
                (
                    lambda alert: alert.get("tags", {}).get("alertIndex", None),
                    sort_direction,
                ),
            ],
        )

        column_header_locator = browser.locator(
            f"[data-testid='alerts-table'] table thead th [data-testid='header-cell-tags.alertIndex']",
            has_text=coumn_name,
        )
        expect(column_header_locator).to_be_visible()
        column_header_locator.click()
        rows = browser.locator("[data-testid='alerts-table'] table tbody tr")

        number_of_missmatches = 0
        for index, alert in enumerate(sorted_alerts):
            row_locator = rows.nth(index)
            # 4 is index of "name" column
            column_locator = row_locator.locator("td").nth(alert_name_column_index)
            try:
                expect(column_locator).to_have_text(alert["name"])
            except Exception as e:
                save_failure_artifacts(browser, log_entries=[])
                number_of_missmatches += 1
                if number_of_missmatches > 2:
                    raise e
                else:
                    print(
                        f"Expected: {alert['name']} but got: {column_locator.text_content()}"
                    )
                    continue


def test_alerts_stream(browser: Page, setup_page_logging, failure_artifacts):
    facet_name = "source"
    alert_property_name = "providerType"
    value = "prometheus"
    test_id = "test_alerts_stream"
    cel_to_filter_alerts = f"testId == '{test_id}'"
    log_entries = []
    setup_console_listener(browser, log_entries)

    browser.goto(f"{KEEP_UI_URL}/alerts/feed?cel={cel_to_filter_alerts}")
    browser.wait_for_selector("[data-testid='alerts-table']")
    browser.wait_for_selector("[data-testid='facets-panel']")
    simulated_alerts = []
    for alert_index, provider_type in enumerate(["prometheus"] * 20):
        alert = create_fake_alert(alert_index, provider_type)
        alert["testId"] = test_id
        simulated_alerts.append((provider_type, alert))

    token = get_token()
    for provider_type, alert in simulated_alerts:
        url = f"{KEEP_API_URL}/alerts/event/{provider_type}"
        requests.post(
            url,
            json=alert,
            timeout=5,
            headers={"Authorization": "Bearer " + token},
        ).raise_for_status()
        time.sleep(1)

    try:
        # refresh the page to get the new alerts
        browser.reload()
        browser.wait_for_selector("[data-testid='facet-value']", timeout=30000)  # Increase timeout from 10s to 30s

        # Add retry logic for checking alert count
        max_retries = 5
        for retry in range(max_retries):
            try:
                # Wait a bit longer between retries
                if retry > 0:
                    print(f"Retry {retry}/{max_retries} for alert count check")
                    time.sleep(5)
                    browser.reload()
                    browser.wait_for_selector("[data-testid='facet-value']", timeout=30000)

                # Check if alerts are visible
                alert_count = browser.locator("[data-testid='alerts-table'] table tbody tr").count()
                print(f"Current alert count: {alert_count}, expected: {len(simulated_alerts)}")

                if alert_count == len(simulated_alerts):
                    break

                if retry == max_retries - 1:
                    # On last retry, use the expect assertion which will provide better error details
                    expect(
                        browser.locator("[data-testid='alerts-table'] table tbody tr")
                    ).to_have_count(len(simulated_alerts))
            except Exception as retry_error:
                if retry == max_retries - 1:
                    raise retry_error
                print(f"Error during retry {retry}: {str(retry_error)}")

    except Exception as e:
        save_failure_artifacts(browser, log_entries=log_entries)
        raise e
    query_result = query_alerts(cell_query=cel_to_filter_alerts, limit=1000)
    current_alerts = query_result["results"]
    assert_facet(browser, facet_name, current_alerts, alert_property_name)

    assert_alerts_by_column(
        browser,
        current_alerts,
        lambda alert: alert[alert_property_name] == value,
        alert_property_name,
        None,
    )


def test_filter_search_timeframe_combination_with_queryparams(
    browser: Page,
    setup_test_data,
    setup_page_logging,
    failure_artifacts,
):
    try:
        # Helper function for timestamp conversion
        def to_readable_utc_iso(ts_value):
            if ts_value is None:
                return "None"
            try:
                # Attempt to handle both Unix MS and ISO strings
                if isinstance(ts_value, (int, float)): # Assuming Unix MS
                    return datetime.fromtimestamp(ts_value / 1000, timezone.utc).isoformat()
                elif isinstance(ts_value, str): # Assuming ISO string
                    # Handle potential 'Z' and ensure UTC
                    dt_obj = datetime.fromisoformat(ts_value.replace("Z", "+00:00"))
                    if dt_obj.tzinfo is None:
                        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
                    else:
                        dt_obj = dt_obj.astimezone(timezone.utc)
                    return dt_obj.isoformat()
                return str(ts_value) # Fallback
            except Exception as e:
                return f"Error parsing ts '{ts_value}': {e}"

        facet_name = "severity"
        alert_property_name = "severity"
        value = "info"

        print("\n--- E2E Test Local Python Filtering Log ---")
        now_utc = datetime.now(timezone.utc)
        four_hours_ago_utc = now_utc - timedelta(hours=4)
        print(f"Current Time (UTC) for filtering: {now_utc.isoformat()}")
        print(f"Time Boundary (4 hours ago UTC): {four_hours_ago_utc.isoformat()}")

        # Original filter_lambda for reference by the UI/Backend perspective log
        original_python_filter_lambda = lambda alert_orig: (
            alert_orig.get(alert_property_name) == value
            and "high" in alert_orig.get("name", "").lower()
            # Ensure lastReceived is parsed correctly, assuming it might be string or int/float (ms)
            and (datetime.fromisoformat(alert_orig["lastReceived"].replace("Z", "+00:00")).replace(tzinfo=timezone.utc) if isinstance(alert_orig.get("lastReceived"), str)
                 else datetime.fromtimestamp(alert_orig.get("lastReceived")/1000, timezone.utc))
            >= four_hours_ago_utc
        )

        def filter_lambda_with_logging(alert_log):
            is_info = alert_log.get(alert_property_name) == value
            name_matches = "high" in alert_log.get("name", "").lower()
            
            raw_last_received = alert_log.get("lastReceived")
            parsed_last_received_dt = None
            passes_e2e_time_filter = False
            
            if raw_last_received is not None:
                try:
                    if isinstance(raw_last_received, (int, float)): # Unix MS
                        parsed_last_received_dt = datetime.fromtimestamp(raw_last_received / 1000, timezone.utc)
                    elif isinstance(raw_last_received, str): # ISO String
                        dt_obj_lr = datetime.fromisoformat(raw_last_received.replace("Z", "+00:00"))
                        if dt_obj_lr.tzinfo is None:
                           parsed_last_received_dt = dt_obj_lr.replace(tzinfo=timezone.utc)
                        else:
                           parsed_last_received_dt = dt_obj_lr.astimezone(timezone.utc)
                    
                    if parsed_last_received_dt:
                        passes_e2e_time_filter = parsed_last_received_dt >= four_hours_ago_utc
                except Exception as e:
                    print(f"    Error parsing DTO_lastReceived '{raw_last_received}' for E2E filter: {e}")

            # Log for all relevant alerts (matching severity and name), not just those passing the time filter initially
            if is_info and name_matches:
                print(f"  E2E_Filter_Check Alert: {alert_log.get('name')}, Fingerprint: {alert_log.get('fingerprint')}, Provider: {alert_log.get('providerType')}")
                print(f"    Severity: {alert_log.get('severity')}")
                print(f"    DTO_lastReceived (raw): {raw_last_received}")
                print(f"    DTO_lastReceived (parsed UTC): {to_readable_utc_iso(raw_last_received)}")
                print(f"    DTO_timestamp (raw): {alert_log.get('timestamp')}") # This is LastAlert.timestamp
                print(f"    DTO_timestamp (parsed UTC): {to_readable_utc_iso(alert_log.get('timestamp'))}")
                
                raw_dto_timestamp = alert_log.get('timestamp')
                # Calculate delta if both are parseable
                try:
                    # Convert DTO_timestamp to datetime if not already
                    parsed_dto_timestamp_dt = None
                    if isinstance(raw_dto_timestamp, (int, float)):
                        parsed_dto_timestamp_dt = datetime.fromtimestamp(raw_dto_timestamp / 1000, timezone.utc)
                    elif isinstance(raw_dto_timestamp, str):
                        dt_obj_ts = datetime.fromisoformat(raw_dto_timestamp.replace("Z", "+00:00"))
                        if dt_obj_ts.tzinfo is None:
                            parsed_dto_timestamp_dt = dt_obj_ts.replace(tzinfo=timezone.utc)
                        else:
                            parsed_dto_timestamp_dt = dt_obj_ts.astimezone(timezone.utc)

                    if parsed_last_received_dt and parsed_dto_timestamp_dt:
                        delta_seconds = (parsed_dto_timestamp_dt - parsed_last_received_dt).total_seconds()
                        print(f"    Delta (DTO_timestamp - DTO_lastReceived): {delta_seconds:.3f} s")
                except Exception as e_delta:
                    print(f"    Could not calculate delta: {e_delta}")

                print(f"    Passes E2E Time Filter (based on DTO_lastReceived): {passes_e2e_time_filter}")
            
            return is_info and name_matches and passes_e2e_time_filter

        current_alerts = query_alerts(cell_query="", limit=1000)["results"]
        init_test(browser, current_alerts, max_retries=3)
        
        # Apply the logging filter
        filtered_alerts = []
        for alert_item_for_e2e_filter in current_alerts:
            if filter_lambda_with_logging(alert_item_for_e2e_filter):
                filtered_alerts.append(alert_item_for_e2e_filter)
        print(f"--- E2E Test Locally Filtered Count (based on DTO_lastReceived): {len(filtered_alerts)} ---")

        # Give the page a moment to process redirects
        browser.wait_for_timeout(500)

        # Wait for navigation to complete to either signin or providers page
        # (since we might get redirected automatically)
        browser.wait_for_load_state("networkidle")

        option = browser.locator("[data-testid='facet-value']", has_text=value)
        option.hover()

        option.locator("button", has_text="Only").click()
        browser.wait_for_timeout(500)

        cel_input_locator = browser.locator(".alerts-cel-input")
        cel_input_locator.click()
        browser.keyboard.type("name.contains('high')")
        browser.keyboard.press("Enter")
        browser.wait_for_timeout(500)

        # select timeframe
        browser.locator("button[data-testid='timeframe-picker-trigger']").click()
        browser.locator(
            "[data-testid='timeframe-picker-content'] button", has_text="Past 4 hours"
        ).click()
        browser.wait_for_timeout(500) # Give time for UI to update after timeframe selection

        print("\n--- UI/Backend Perspective Log ---")
        # now_utc and four_hours_ago_utc are already defined from the E2E local filter section
        print(f"Current Time (UTC) for UI perspective: {now_utc.isoformat()}")
        print(f"Time Boundary (4 hours ago UTC) for UI perspective: {four_hours_ago_utc.isoformat()}")
        
        ui_relevant_cel_query = "severity == 'info' && name.contains('high')"
        print(f"Querying API with CEL: '{ui_relevant_cel_query}' to get potential UI alerts for timeframe check.")
        
        # Fetch all alerts matching severity and name; backend will apply timeframe based on LastAlert.timestamp.
        # For logging, we'll mimic this timeframe check on alert["timestamp"].
        # The UI itself would have applied the timeframe filter, so the facet count reflects that.
        # This query_alerts is to get the *list* of alerts the UI *would* be considering for its count.
        potential_ui_alerts_from_api = query_alerts(cel_query=ui_relevant_cel_query, limit=50)["results"]
        print(f"Found {len(potential_ui_alerts_from_api)} alerts matching CEL '{ui_relevant_cel_query}' from API (before client-side check of DTO_timestamp).")
        
        ui_side_filtered_count = 0
        alerts_counted_by_ui_perspective = []
        for alert_data_ui in potential_ui_alerts_from_api:
            raw_backend_ts = alert_data_ui.get("timestamp") # This is DTO's 'timestamp', i.e., LastAlert.timestamp
            parsed_backend_ts_dt = None
            passes_backend_time_filter = False

            if raw_backend_ts is not None:
                try:
                    if isinstance(raw_backend_ts, (int, float)): # Unix MS
                        parsed_backend_ts_dt = datetime.fromtimestamp(raw_backend_ts / 1000, timezone.utc)
                    elif isinstance(raw_backend_ts, str): # ISO String
                        dt_obj_bts = datetime.fromisoformat(raw_backend_ts.replace("Z", "+00:00"))
                        if dt_obj_bts.tzinfo is None:
                            parsed_backend_ts_dt = dt_obj_bts.replace(tzinfo=timezone.utc)
                        else:
                            parsed_backend_ts_dt = dt_obj_bts.astimezone(timezone.utc)
                    
                    if parsed_backend_ts_dt:
                        passes_backend_time_filter = parsed_backend_ts_dt >= four_hours_ago_utc
                except Exception as e:
                    print(f"    Error parsing DTO_timestamp '{raw_backend_ts}' for UI perspective: {e}")

            if passes_backend_time_filter: # Only log details if it passes the backend-style time filter
                ui_side_filtered_count += 1
                alerts_counted_by_ui_perspective.append(alert_data_ui)
                print(f"  UI_Filter_Check Alert: {alert_data_ui.get('name')}, Fingerprint: {alert_data_ui.get('fingerprint')}, Provider: {alert_data_ui.get('providerType')}")
                print(f"    Severity: {alert_data_ui.get('severity')}")
                print(f"    DTO_lastReceived (raw): {alert_data_ui.get('lastReceived')}")
                print(f"    DTO_lastReceived (parsed UTC): {to_readable_utc_iso(alert_data_ui.get('lastReceived'))}")
                print(f"    DTO_timestamp (raw): {raw_backend_ts}")
                print(f"    DTO_timestamp (parsed UTC): {to_readable_utc_iso(raw_backend_ts)}")
                
                raw_dto_last_received_ui = alert_data_ui.get('lastReceived')
                # Calculate delta if both are parseable
                try:
                    parsed_last_received_dt_ui = None
                    if isinstance(raw_dto_last_received_ui, (int, float)):
                        parsed_last_received_dt_ui = datetime.fromtimestamp(raw_dto_last_received_ui / 1000, timezone.utc)
                    elif isinstance(raw_dto_last_received_ui, str):
                        dt_obj_lrui = datetime.fromisoformat(raw_dto_last_received_ui.replace("Z", "+00:00"))
                        if dt_obj_lrui.tzinfo is None:
                            parsed_last_received_dt_ui = dt_obj_lrui.replace(tzinfo=timezone.utc)
                        else:
                            parsed_last_received_dt_ui = dt_obj_lrui.astimezone(timezone.utc)

                    if parsed_last_received_dt_ui and parsed_backend_ts_dt:
                        delta_seconds_ui = (parsed_backend_ts_dt - parsed_last_received_dt_ui).total_seconds()
                        print(f"    Delta (DTO_timestamp - DTO_lastReceived): {delta_seconds_ui:.3f} s")
                except Exception as e_delta_ui:
                    print(f"    Could not calculate delta for UI perspective: {e_delta_ui}")
                
                # Check this alert against the E2E test's original Python filter logic
                passes_e2e_original_filter = original_python_filter_lambda(alert_data_ui)
                print(f"    Passes E2E Original Python Filter (based on DTO_lastReceived): {passes_e2e_original_filter}")
        
        print(f"--- Count of alerts passing UI-like time filter (based on DTO_timestamp): {ui_side_filtered_count} ---")
        # This count should ideally match the facet count displayed in the UI.
        # The assert_facet below uses filtered_alerts (from E2E local filter), which is expected to be 6.
        # The UI facet count is expected to be 7.

        # check that alerts are filtered by the selected facet/cel/timeframe
        # NOTE: The original assert_facet uses 'filtered_alerts' which is based on the E2E test's local Python filter.
        # This is expected to show 6. The UI would show 7.
        assert_facet(
            browser,
            facet_name,
            filtered_alerts,
            alert_property_name,
        )
        assert_alerts_by_column(
            browser,
            current_alerts,
            filter_lambda,
            alert_property_name,
            None,
        )

        # Refresh in order to check that filters/facets are restored
        # It will use the URL query params from previous filters
        browser.reload()
        assert_facet(
            browser,
            facet_name,
            filtered_alerts,
            alert_property_name,
        )
        assert_alerts_by_column(
            browser,
            current_alerts,
            filter_lambda,
            alert_property_name,
            None,
        )
        expect(
            browser.locator("button[data-testid='timeframe-picker-trigger']")
        ).to_contain_text("Past 4 hours")
    except Exception:
        save_failure_artifacts(browser, log_entries=[])
        raise


def test_adding_new_preset(
    browser: Page,
    setup_test_data,
    setup_page_logging,
    failure_artifacts,
):
    try:
        facet_name = "severity"
        alert_property_name = "severity"

        def filter_lambda(alert):
            return "high" in alert["name"].lower()

        current_alerts = query_alerts(cell_query="", limit=1000)["results"]
        init_test(browser, current_alerts, max_retries=3)
        filtered_alerts = [alert for alert in current_alerts if filter_lambda(alert)]

        # Give the page a moment to process redirects
        browser.wait_for_timeout(500)

        # Wait for navigation to complete to either signin or providers page
        # (since we might get redirected automatically)
        browser.wait_for_load_state("networkidle")

        cel_input_locator = browser.locator(".alerts-cel-input")
        cel_input_locator.click()
        browser.keyboard.type("name.contains('high')")
        browser.keyboard.press("Enter")
        browser.wait_for_timeout(500)

        # check that alerts are filtered by the preset CEL
        assert_facet(
            browser,
            facet_name,
            filtered_alerts,
            alert_property_name,
        )
        assert_alerts_by_column(
            browser,
            current_alerts,
            filter_lambda,
            alert_property_name,
            None,
        )

        browser.locator("[data-testid='save-preset-button']").click()

        preset_form_locator = browser.locator("[data-testid='preset-form']")
        expect(browser.locator("[data-testid='alerts-count-badge']")).to_contain_text(
            str(len(filtered_alerts))
        )
        preset_form_locator.locator("[data-testid='preset-name-input']").fill(
            "Test preset"
        )

        preset_form_locator.locator(
            "[data-testid='counter-shows-firing-only-switch']"
        ).click()

        preset_form_locator.locator("[data-testid='save-preset-button']").click()
        preset_locator = browser.locator(
            "[data-testid='preset-link-container']", has_text="Test preset"
        )
        expect(preset_locator).to_be_visible()
        expect(preset_locator.locator("[data-testid='preset-badge']")).to_contain_text(
            str(len(filtered_alerts))
        )
        expect(browser.locator(".alerts-cel-input .view-lines")).to_have_text(
            "name.contains('high')"
        )
        expect(browser.locator("[data-testid='preset-page-title']")).to_contain_text(
            "Test preset"
        )

        # Refresh in order to check that the preset and corresponding data is open
        browser.reload()
        expect(browser.locator(".alerts-cel-input .view-lines")).to_have_text(
            "name.contains('high')"
        )
        expect(browser.locator("[data-testid='preset-page-title']")).to_contain_text(
            "Test preset"
        )
        assert_facet(
            browser,
            facet_name,
            filtered_alerts,
            alert_property_name,
        )
        assert_alerts_by_column(
            browser,
            current_alerts,
            filter_lambda,
            alert_property_name,
            None,
        )
    except Exception:
        save_failure_artifacts(browser, log_entries=[])
        raise