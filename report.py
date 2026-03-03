import os
import sys
import time
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict

import requests
import urllib3
import pandas as pd
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# ============================================
# CONFIGURATION
# ============================================

WORKDAY_CONFIG = {
    'client_id': os.getenv('WORKDAY_CLIENT_ID'),
    'client_secret': os.getenv('WORKDAY_CLIENT_SECRET'),
    'token_url': os.getenv('WORKDAY_TOKEN_URL'),
    'api_url': os.getenv('WORKDAY_API_URL'),
    'scope': os.getenv('WORKDAY_SCOPE'),
    'campaign_start_date': os.getenv('CAMPAIGN_START_DATE', '2025-04-27'),
}

PROOFPOINT_CONFIG = {
    'base_url': os.getenv('PROOFPOINT_BASE_URL'),
    'api_key': os.getenv('PROOFPOINT_API_KEY'),
    'start_date': os.getenv('PROOFPOINT_START_DATE', '2025-04-27'),
    'end_date': os.getenv('PROOFPOINT_END_DATE', '2025-05-10'),
    'page_size': int(os.getenv('PROOFPOINT_PAGE_SIZE', '500')),
    'verify_ssl': os.getenv('PROOFPOINT_VERIFY_SSL', 'False').lower() == 'true',
    'rate_limit_delay': float(os.getenv('PROOFPOINT_RATE_LIMIT_DELAY', '1.0')),
    'retry_delay': float(os.getenv('PROOFPOINT_RETRY_DELAY', '5.0')),
    'max_retries': int(os.getenv('PROOFPOINT_MAX_RETRIES', '3')),
}

OUTPUT_CONFIG = {
    'output_excel': os.getenv('OUTPUT_EXCEL_PATH', r'C:\WorkdaySADFeed\Merged_Campaign_Details_May25.xlsx'),
    'output_csv': os.getenv('OUTPUT_CSV_PATH', r'C:\WorkdaySADFeed\Merged_Campaign_Details_May25.csv'),
}

# Logging configuration (optional via .env)
LOGGING_CONFIG = {
    "level": os.getenv("LOG_LEVEL", "INFO").upper(),
    "to_file": os.getenv("LOG_TO_FILE", "false").lower() == "true",
    "file_path": os.getenv("LOG_FILE_PATH", ""),  # if blank, will default near output_excel
    "max_bytes": int(os.getenv("LOG_MAX_BYTES", "5242880")),  # 5MB
    "backup_count": int(os.getenv("LOG_BACKUP_COUNT", "5")),
    "use_utc": os.getenv("LOG_USE_UTC", "false").lower() == "true",
}

PROOFPOINT_FIELDS = [
    'Email Address',
    'First Name',
    'Last Name',
    'Campaign Guid',
    'Users Guid',
    'Campaign Title',
    'Phishing Template',
    'Date Sent',
    'Primary Email Opened',
    'Date Email Opened',
    'Multi Email Open',
    'Email Opened IP Address',
    'Email Opened Browser',
    'Email Opened Browser Version',
    'Email Opened OS',
    'Email Opened OS Version',
    'Primary Clicked',
    'Date Clicked',
    'Multi Click Event',
    'Clicked IP Address',
    'Clicked Browser',
    'Clicked Browser Version',
    'Clicked OS',
    'Clicked OS Version',
    'Primary Compromised Login',
    'Date Login Compromised',
    'Multi Compromised',
    'Primary Attachment Open',
    'Date Attachment Open',
    'Multi Attachment Open',
    'Reported',
    'Date Reported',
    'Passed?',
    'Whois ISP',
    'Whois Country',
    'Teachable Moment Started',
    'Acknowledgement Completed',
    'False Positive',
]

WORKDAY_FIELDS = [
    'Level5SupervioryOrganizationid',
    'Level5SupervioryOrganizationdesc',
    'Level6SupervioryOrganizationid',
    'Level6SupervioryOrganizationdesc',
    'Level3SupervioryOrganizationid',
    'Level3SupervioryOrganizationdesc',
    'Level4SupervioryOrganizationid',
    'Level4SupervioryOrganizationdesc',
    'WorkdayEmployeeType',
    'TerminationDate',
    'ReHireDate',
    'HireDate',
    'InternetEmailAddress',
    'StatusCode',
    'GlobalId',
    'SystemLogonId',
    'StatusDescription',
    'Title',
    'WorkCountryDescription',
    'SupervisorGlobalId',
    'OnboardDate',
    'RetirementDate',
    'SupervisorEmail',
    'SupervisorSystemId',
    'JobSubFunctionCode',
    'JobSubFunctionDescription',
]

# ============================================
# LOGGING SETUP
# ============================================

def setup_logging() -> logging.Logger:
    """
    Production-friendly logging:
      - Console logs (CI/CD friendly)
      - Optional rotating file logs
    """
    logger = logging.getLogger("campaign_merge")
    logger.setLevel(getattr(logging, LOGGING_CONFIG["level"], logging.INFO))
    logger.propagate = False  # avoid duplicate logs if root handlers exist

    # If handlers already exist (e.g., in notebooks), do not add duplicates
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Use UTC timestamps if requested
    if LOGGING_CONFIG["use_utc"]:
        formatter.converter = time.gmtime

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logger.level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Optional file handler
    if LOGGING_CONFIG["to_file"]:
        file_path = LOGGING_CONFIG["file_path"].strip()

        # Default file path near Excel output if not provided
        if not file_path:
            out_dir = os.path.dirname(OUTPUT_CONFIG["output_excel"])
            file_path = os.path.join(out_dir, "logs", "campaign_merge.log")

        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        file_handler = RotatingFileHandler(
            file_path,
            maxBytes=LOGGING_CONFIG["max_bytes"],
            backupCount=LOGGING_CONFIG["backup_count"],
            encoding="utf-8",
        )
        file_handler.setLevel(logger.level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        logger.info("File logging enabled: %s", file_path)

    return logger


logger = setup_logging()

# ============================================
# HELPER FUNCTIONS
# ============================================

def parse_timestamp(timestamp_str):
    """Parse ISO 8601 timestamp to datetime object."""
    if not timestamp_str or pd.isna(timestamp_str):
        return None
    try:
        if isinstance(timestamp_str, str):
            timestamp_str = timestamp_str.replace('Z', '+00:00')
            return pd.to_datetime(timestamp_str)
        return pd.to_datetime(timestamp_str)
    except Exception as e:
        logger.warning("Failed to parse timestamp '%s': %s", timestamp_str, e)
        return None


def is_false_positive(date_sent, date_clicked, whois_isp):
    """
    Determine if a click is a false positive based on:
      1) Whois ISP contains 'Microsoft Azure'
      2) Time between sent and clicked <= 60 seconds
    """
    if not date_sent or not date_clicked or not whois_isp:
        return False

    sent_time = parse_timestamp(date_sent)
    clicked_time = parse_timestamp(date_clicked)

    if not sent_time or not clicked_time:
        return False

    is_azure = 'microsoft azure' in str(whois_isp).lower()
    time_diff = abs((clicked_time - sent_time).total_seconds())
    is_fp = is_azure and time_diff <= 60

    if is_fp:
        logger.info(
            "False positive click detected. Sent=%s Clicked=%s Delta=%.2fs ISP=%s",
            date_sent, date_clicked, time_diff, whois_isp
        )

    return is_fp


def add_executive_leadership_column(df):
    """Add 'Executive Leadership' boolean column based on JobSubFunctionCode."""
    if 'JobSubFunctionCode' in df.columns:
        df['Executive Leadership'] = df['JobSubFunctionCode'].apply(
            lambda x: True if pd.notna(x) and str(x).strip() == 'JFA000011' else False
        )
        exec_count = int(df['Executive Leadership'].sum())
        logger.info("Executive Leadership column added. Executives identified=%d", exec_count)
    else:
        df['Executive Leadership'] = False
        logger.warning("'JobSubFunctionCode' not found. Executive Leadership set to False for all rows.")
    return df


# ============================================
# WORKDAY API FUNCTIONS
# ============================================

def get_workday_access_token():
    """Get access token for Workday API."""
    logger.info("Requesting Workday access token...")
    data = {
        'grant_type': 'client_credentials',
        'client_id': WORKDAY_CONFIG['client_id'],
        'client_secret': WORKDAY_CONFIG['client_secret'],
        'scope': WORKDAY_CONFIG['scope'],
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    try:
        response = requests.post(WORKDAY_CONFIG['token_url'], data=data, headers=headers)
        response.raise_for_status()
        token_info = response.json()
        logger.info("Workday token acquired successfully.")
        return token_info['access_token']
    except Exception as e:
        logger.exception("Unable to acquire Workday token: %s", e)
        raise


def fetch_workday_workers():
    """Fetch workers from Workday API - Active OR Terminated on/after campaign start."""
    logger.info("Fetching Workday worker data...")
    logger.info("Date filter: Active OR TerminationDate >= %s", WORKDAY_CONFIG['campaign_start_date'])

    access_token = get_workday_access_token()
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json',
    }

    all_records = []
    page_size = 1000
    skip = 0
    select_fields = ','.join(WORKDAY_FIELDS)

    while True:
        filter_query = (
            f"$filter=InternetEmailAddress ne null and "
            f"(StatusDescription eq 'Active' or "
            f"(TerminationDate ne null and TerminationDate ge '{WORKDAY_CONFIG['campaign_start_date']}'))"
        )

        paginated_url = (
            f"{WORKDAY_CONFIG['api_url']}?"
            f"{filter_query}&$select={select_fields}&$top={page_size}&$skip={skip}"
        )

        try:
            response = requests.get(paginated_url, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
            records = data.get('value', [])

            if not records:
                break

            all_records.extend(records)
            logger.info("Retrieved %d Workday records (total=%d).", len(records), len(all_records))
            skip += page_size

        except requests.exceptions.RequestException as e:
            logger.error("Workday fetch failed: %s", e)
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                logger.error("Workday response details (truncated): %s", e.response.text[:500])
            break

    logger.info("Total Workday records fetched: %d", len(all_records))
    return all_records


# ============================================
# PROOFPOINT API FUNCTIONS
# ============================================

def fetch_proofpoint_records():
    """
    Fetch all records from Proofpoint API.

    Fixes included:
      1) Uses campaign start/end date filters so users with no actions are included.
      2) Explicitly sets filter[_includenoaction]=TRUE to prevent silent behavior changes.
      3) Validates fetched count vs meta.count to detect partial fetches.
    """
    logger.info("Fetching Proofpoint phishing data...")
    logger.info("Using campaign start/end date filters (includes no-action users).")
    logger.info("Including deleted users for parity with UI reporting.")

    all_records = []
    page_number = 1
    has_more_pages = True
    expected_total = None

    headers = {'x-apikey-token': PROOFPOINT_CONFIG['api_key']}

    while has_more_pages:
        logger.info("Fetching Proofpoint page %d...", page_number)

        params = {
            'page[number]': page_number,
            'page[size]': PROOFPOINT_CONFIG['page_size'],
            'filter[_campaignstartdate_start]': PROOFPOINT_CONFIG['start_date'],
            'filter[_campaignstartdate_end]': PROOFPOINT_CONFIG['end_date'],
            'filter[_includenoaction]': 'TRUE',
            'filter[_includedeletedusers]': 'TRUE',
        }
        params = {k: v for k, v in params.items() if v is not None}

        retry_count = 0
        success = False

        while retry_count < PROOFPOINT_CONFIG['max_retries'] and not success:
            try:
                if page_number > 1 or retry_count > 0:
                    delay = PROOFPOINT_CONFIG['rate_limit_delay']
                    logger.info("Rate limiting enabled. Sleeping %.2fs...", delay)
                    time.sleep(delay)

                response = requests.get(
                    PROOFPOINT_CONFIG['base_url'],
                    headers=headers,
                    params=params,
                    timeout=30,
                    verify=PROOFPOINT_CONFIG['verify_ssl'],
                )

                if response.status_code == 429:
                    retry_count += 1
                    retry_after = int(response.headers.get('Retry-After', PROOFPOINT_CONFIG['retry_delay']))
                    logger.warning(
                        "HTTP 429 (Too Many Requests). Retry %d/%d. Sleeping %ds...",
                        retry_count, PROOFPOINT_CONFIG['max_retries'], retry_after
                    )
                    time.sleep(retry_after)
                    continue

                if response.status_code == 504:
                    retry_count += 1
                    wait_time = PROOFPOINT_CONFIG['retry_delay'] * retry_count
                    logger.warning(
                        "HTTP 504 (Gateway Timeout). Retry %d/%d. Sleeping %ds...",
                        retry_count, PROOFPOINT_CONFIG['max_retries'], wait_time
                    )
                    time.sleep(wait_time)
                    continue

                response.raise_for_status()
                data = response.json()

                if expected_total is None:
                    meta = data.get('meta', {})
                    expected_total = meta.get('count')
                    if expected_total is not None:
                        logger.info("Proofpoint API reports total record count: %s", expected_total)

                if data.get('data') and len(data['data']) > 0:
                    all_records.extend(data['data'])
                    logger.info("Retrieved %d Proofpoint records (total=%d).", len(data['data']), len(all_records))
                    page_number += 1
                    success = True
                else:
                    has_more_pages = False
                    success = True

            except requests.exceptions.HTTPError as e:
                status = getattr(e.response, "status_code", None)
                if status == 429:
                    retry_count += 1
                    retry_after = int(e.response.headers.get('Retry-After', PROOFPOINT_CONFIG['retry_delay']))
                    logger.warning("HTTP 429. Retry %d/%d. Sleeping %ds...",
                                   retry_count, PROOFPOINT_CONFIG['max_retries'], retry_after)
                    time.sleep(retry_after)
                elif status == 504:
                    retry_count += 1
                    wait_time = PROOFPOINT_CONFIG['retry_delay'] * retry_count
                    logger.warning("HTTP 504. Retry %d/%d. Sleeping %ds...",
                                   retry_count, PROOFPOINT_CONFIG['max_retries'], wait_time)
                    time.sleep(wait_time)
                else:
                    logger.error("HTTP error while fetching Proofpoint data: %s", e)
                    has_more_pages = False
                    success = True

            except requests.exceptions.RequestException as e:
                logger.error("Request error while fetching Proofpoint data: %s", e)
                if retry_count < PROOFPOINT_CONFIG['max_retries'] - 1:
                    retry_count += 1
                    wait_time = PROOFPOINT_CONFIG['retry_delay']
                    logger.warning("Retrying in %ds (%d/%d)...",
                                   wait_time, retry_count, PROOFPOINT_CONFIG['max_retries'])
                    time.sleep(wait_time)
                else:
                    has_more_pages = False
                    success = True

        if retry_count >= PROOFPOINT_CONFIG['max_retries']:
            logger.warning("Max retries reached for page %d. Stopping pagination.", page_number)
            has_more_pages = False

    logger.info("Total Proofpoint records fetched: %d", len(all_records))

    if expected_total is not None:
        if len(all_records) < expected_total:
            logger.warning("Expected %s records but fetched %d. Output may be incomplete.",
                           expected_total, len(all_records))
        else:
            logger.info("Record count validated: %d / %s", len(all_records), expected_total)

    return all_records


def transform_proofpoint_data(records):
    """Transform Proofpoint API data with false positive detection."""
    logger.info("Transforming Proofpoint data (includes false positive detection)...")

    grouped = defaultdict(list)
    for record in records:
        attrs = record['attributes']
        key = f"{attrs['user_guid']}_{attrs['campaign_guid']}"
        grouped[key].append(record)

    transformed_data = []
    false_positive_count = 0

    for _, events in grouped.items():
        events_sorted = sorted(events, key=lambda x: x['attributes']['eventtimestamp'])
        first_event = events_sorted[0]['attributes']

        email_views = [e for e in events_sorted if e['attributes']['eventtype'] == 'Email View']
        email_clicks = [e for e in events_sorted if e['attributes']['eventtype'] == 'Email Click']
        data_submissions = [e for e in events_sorted if e['attributes']['eventtype'] == 'Data Submission']
        attachment_opens = [e for e in events_sorted if e['attributes']['eventtype'] == 'Attachment Open']
        tm_sent = [e for e in events_sorted if e['attributes']['eventtype'] == 'TM Sent']
        tm_complete = [e for e in events_sorted if e['attributes']['eventtype'] == 'TM Complete']
        reported = [e for e in events_sorted if e['attributes']['eventtype'] == 'Reported']

        campaign_type = first_event.get('campaigntype', '')
        if campaign_type == 'Drive By':
            failure_condition = len(email_clicks) > 0
        elif campaign_type == 'Data Entry Campaign':
            failure_condition = len(data_submissions) > 0
        elif campaign_type == 'Attachment':
            failure_condition = len(attachment_opens) > 0
        else:
            failure_condition = False

        # Prefer events with Whois data
        if email_clicks:
            whois_source = email_clicks[0]['attributes']
        elif data_submissions:
            whois_source = data_submissions[0]['attributes']
        elif attachment_opens:
            whois_source = attachment_opens[0]['attributes']
        elif email_views:
            whois_source = email_views[0]['attributes']
        else:
            whois_source = first_event

        def get_first_attr(event_list, attr_name):
            return event_list[0]['attributes'].get(attr_name) if event_list else None

        def bool_to_str(condition):
            return 'TRUE' if condition else 'FALSE'

        date_sent = first_event.get('senttimestamp')
        date_clicked = get_first_attr(email_clicks, 'eventtimestamp')
        whois_isp = whois_source.get('whois_isp')
        primary_clicked = len(email_clicks) > 0

        is_fp = is_false_positive(date_sent, date_clicked, whois_isp)
        if is_fp:
            primary_clicked = False
            false_positive_count += 1

        record_out = {
            'Email Address': first_event.get('useremailaddress'),
            'First Name': first_event.get('userfirstname'),
            'Last Name': first_event.get('userlastname'),
            'Campaign Guid': first_event.get('campaign_guid'),
            'Users Guid': first_event.get('user_guid'),
            'Campaign Title': first_event.get('campaignname'),
            'Phishing Template': first_event.get('templatename'),
            'Date Sent': date_sent,
            'Primary Email Opened': bool_to_str(len(email_views) > 0),
            'Date Email Opened': get_first_attr(email_views, 'eventtimestamp'),
            'Multi Email Open': max(0, len(email_views) - 1),
            'Email Opened IP Address': get_first_attr(email_views, 'ip_address'),
            'Email Opened Browser': get_first_attr(email_views, 'browser'),
            'Email Opened Browser Version': get_first_attr(email_views, 'browser_version'),
            'Email Opened OS': get_first_attr(email_views, 'os'),
            'Email Opened OS Version': get_first_attr(email_views, 'os_version'),
            'Primary Clicked': bool_to_str(primary_clicked),
            'Date Clicked': date_clicked,
            'Multi Click Event': max(0, len(email_clicks) - 1),
            'Clicked IP Address': get_first_attr(email_clicks, 'ip_address'),
            'Clicked Browser': get_first_attr(email_clicks, 'browser'),
            'Clicked Browser Version': get_first_attr(email_clicks, 'browser_version'),
            'Clicked OS': get_first_attr(email_clicks, 'os'),
            'Clicked OS Version': get_first_attr(email_clicks, 'os_version'),
            'Primary Compromised Login': bool_to_str(len(data_submissions) > 0),
            'Date Login Compromised': get_first_attr(data_submissions, 'eventtimestamp'),
            'Multi Compromised': max(0, len(data_submissions) - 1),
            'Primary Attachment Open': bool_to_str(len(attachment_opens) > 0),
            'Date Attachment Open': get_first_attr(attachment_opens, 'eventtimestamp'),
            'Multi Attachment Open': max(0, len(attachment_opens) - 1),
            'Reported': bool_to_str(len(reported) > 0),
            'Date Reported': get_first_attr(reported, 'eventtimestamp'),
            'Passed?': bool_to_str(not failure_condition),
            'Whois ISP': whois_isp,
            'Whois Country': whois_source.get('whois_country'),
            'Teachable Moment Started': bool_to_str(len(tm_sent) > 0),
            'Acknowledgement Completed': bool_to_str(len(tm_complete) > 0),
            'False Positive': bool_to_str(is_fp),
        }

        transformed_data.append(record_out)

    logger.info("Transformed %d unique user-campaign records.", len(transformed_data))
    logger.info("False positives detected: %d", false_positive_count)
    return transformed_data


# ============================================
# MERGE AND EXPORT FUNCTIONS
# ============================================

def merge_datasets(proofpoint_df, workday_df):
    """Merge Proofpoint and Workday data on email address."""
    logger.info("Merging Proofpoint and Workday datasets...")

    proofpoint_df_filtered = proofpoint_df[PROOFPOINT_FIELDS].copy()

    workday_df = add_executive_leadership_column(workday_df)
    workday_fields_with_exec = WORKDAY_FIELDS + ['Executive Leadership']
    workday_df_filtered = workday_df[workday_fields_with_exec].copy()

    proofpoint_df_filtered['Email Address'] = proofpoint_df_filtered['Email Address'].str.lower().str.strip()
    workday_df_filtered['InternetEmailAddress'] = workday_df_filtered['InternetEmailAddress'].str.lower().str.strip()

    merged_df = pd.merge(
        proofpoint_df_filtered,
        workday_df_filtered,
        left_on='Email Address',
        right_on='InternetEmailAddress',
        how='left',
        suffixes=('_Proofpoint', '_Workday'),
    )

    if 'InternetEmailAddress' in merged_df.columns:
        merged_df = merged_df.drop(columns=['InternetEmailAddress'])

    matched = int(merged_df['GlobalId'].notna().sum())
    unmatched = int(merged_df['GlobalId'].isna().sum())
    fp_count = int((merged_df['False Positive'] == 'TRUE').sum())
    exec_count = int(merged_df['Executive Leadership'].sum())

    logger.info("Merged records: %d", len(merged_df))
    logger.info("Matched to Workday: %d", matched)
    logger.info("Unmatched: %d", unmatched)
    logger.info("False positives in merged dataset: %d", fp_count)
    logger.info("Executives in merged dataset: %d", exec_count)

    return merged_df


def export_to_excel_with_sheets(workday_df, proofpoint_df, merged_df, output_path):
    """Export data to Excel with three separate sheets."""
    logger.info("Exporting output to Excel (3 worksheets)...")

    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            workday_df.to_excel(writer, sheet_name='Workday Feed', index=False)
            logger.info("Wrote sheet 'Workday Feed' (%d rows).", len(workday_df))

            proofpoint_df.to_excel(writer, sheet_name='Proofpoint Data', index=False)
            logger.info("Wrote sheet 'Proofpoint Data' (%d rows).", len(proofpoint_df))

            merged_df.to_excel(writer, sheet_name='Merged Data', index=False)
            logger.info("Wrote sheet 'Merged Data' (%d rows).", len(merged_df))

            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            max_length = max(max_length, len(str(cell.value)))
                        except Exception:
                            pass
                    worksheet.column_dimensions[column_letter].width = min(max_length + 2, 50)
                worksheet.freeze_panes = 'A2'

        logger.info("Excel saved successfully: %s", output_path)

    except Exception as e:
        logger.exception("Failed to write Excel file: %s", e)
        csv_path = output_path.replace('.xlsx', '_merged.csv')
        merged_df.to_csv(csv_path, index=False, encoding='utf-8')
        logger.info("Wrote fallback CSV instead: %s", csv_path)


def export_merged_to_csv(merged_df, output_csv_path):
    """
    Always export merged dataset to CSV (primary CSV output).
    """
    try:
        os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
        merged_df.to_csv(output_csv_path, index=False, encoding='utf-8')
        logger.info("Merged CSV saved successfully: %s", output_csv_path)
    except Exception as e:
        logger.exception("Failed to write merged CSV file: %s", e)
        raise


# ============================================
# MAIN FUNCTION
# ============================================

def main():
    logger.info("=" * 70)
    logger.info("MERGED PROOFPOINT + WORKDAY CAMPAIGN DETAILS EXPORT")
    logger.info("Features: false positive detection, executive leadership identification, deleted user parity,")
    logger.info("campaign date filtering (includes no-action users), explicit includenoaction, record count validation")
    logger.info("=" * 70)

    logger.info("Proofpoint date range: %s to %s", PROOFPOINT_CONFIG['start_date'], PROOFPOINT_CONFIG['end_date'])
    logger.info("Workday filter: Active OR TerminationDate >= %s", WORKDAY_CONFIG['campaign_start_date'])
    logger.info("Proofpoint page size: %d", PROOFPOINT_CONFIG['page_size'])
    logger.info("Rate limit delay: %.2fs", PROOFPOINT_CONFIG['rate_limit_delay'])
    logger.info("Retry delay: %.2fs", PROOFPOINT_CONFIG['retry_delay'])
    logger.info("Max retries: %d", PROOFPOINT_CONFIG['max_retries'])
    logger.info("False positive detection: Microsoft Azure + <=60s click")
    logger.info("Executive leadership: JobSubFunctionCode == 'JFA000011'")
    logger.info("Proofpoint fields: %d", len(PROOFPOINT_FIELDS))
    logger.info("Workday fields: %d (+ Executive Leadership)", len(WORKDAY_FIELDS))

    if not PROOFPOINT_CONFIG['verify_ssl']:
        logger.warning("SSL verification is disabled.")

    try:
        # Step 1: Fetch Workday data
        workday_records = fetch_workday_workers()
        workday_df = pd.DataFrame(workday_records)

        if workday_df.empty:
            logger.warning("No Workday records returned.")
            workday_df = pd.DataFrame(columns=WORKDAY_FIELDS + ['Executive Leadership'])
        else:
            workday_df = workday_df[workday_df['InternetEmailAddress'].notna()]
            workday_df = workday_df[workday_df['InternetEmailAddress'].str.strip() != '']
            workday_df = add_executive_leadership_column(workday_df)

            active_count = int((workday_df['StatusDescription'] == 'Active').sum())
            terminated_count = int((workday_df['StatusDescription'] != 'Active').sum())
            exec_count = int(workday_df['Executive Leadership'].sum())

            logger.info("Workday records after filtering: %d", len(workday_df))
            logger.info("Active: %d", active_count)
            logger.info("Terminated (on/after %s): %d", WORKDAY_CONFIG['campaign_start_date'], terminated_count)
            logger.info("Executives: %d", exec_count)

        # Step 2: Fetch Proofpoint data
        proofpoint_records = fetch_proofpoint_records()
        if not proofpoint_records:
            logger.error("No Proofpoint records returned. Exiting.")
            sys.exit(1)

        # Step 3: Transform Proofpoint data
        proofpoint_transformed = transform_proofpoint_data(proofpoint_records)
        proofpoint_df = pd.DataFrame(proofpoint_transformed)

        # Step 4: Merge datasets
        merged_df = merge_datasets(proofpoint_df, workday_df)

        # Step 5: Export to Excel with 3 sheets
        export_to_excel_with_sheets(workday_df, proofpoint_df, merged_df, OUTPUT_CONFIG['output_excel'])

        # Step 6: Always export merged dataset to CSV
        export_merged_to_csv(merged_df, OUTPUT_CONFIG['output_csv'])

        # Final Summary
        fp_count = int((proofpoint_df['False Positive'] == 'TRUE').sum())
        exec_count_workday = int(workday_df['Executive Leadership'].sum()) if 'Executive Leadership' in workday_df.columns else 0
        exec_count_merged = int(merged_df['Executive Leadership'].sum()) if 'Executive Leadership' in merged_df.columns else 0
        matched = int(merged_df['GlobalId'].notna().sum())
        unmatched = int(merged_df['GlobalId'].isna().sum())

        logger.info("=" * 70)
        logger.info("EXPORT COMPLETE")
        logger.info("=" * 70)
        logger.info("Workday Feed:    %d records (Executives=%d)", len(workday_df), exec_count_workday)
        logger.info("Proofpoint Data: %d records (False positives=%d)", len(proofpoint_df), fp_count)
        logger.info(
            "Merged Data:     %d records (Matched=%d Unmatched=%d Executives=%d)",
            len(merged_df), matched, unmatched, exec_count_merged
        )
        logger.info("Excel output: %s", OUTPUT_CONFIG['output_excel'])
        logger.info("CSV output:   %s", OUTPUT_CONFIG['output_csv'])

    except KeyboardInterrupt:
        logger.warning("Process interrupted by user.")
        sys.exit(0)

    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()