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
    'campaign_start_date': os.getenv('CAMPAIGN_START_DATE', '2026-03-02'),
}

PROOFPOINT_CONFIG = {
    'base_url': os.getenv('PROOFPOINT_BASE_URL'),
    'api_key': os.getenv('PROOFPOINT_API_KEY'),
    'start_date': os.getenv('PROOFPOINT_START_DATE', '2026-03-02'),
    'end_date': os.getenv('PROOFPOINT_END_DATE', '2026-03-09'),
    'page_size': int(os.getenv('PROOFPOINT_PAGE_SIZE', '500')),
    'verify_ssl': os.getenv('PROOFPOINT_VERIFY_SSL', 'False').lower() == 'true',
    'rate_limit_delay': float(os.getenv('PROOFPOINT_RATE_LIMIT_DELAY', '1.0')),
    'retry_delay': float(os.getenv('PROOFPOINT_RETRY_DELAY', '5.0')),
    'max_retries': int(os.getenv('PROOFPOINT_MAX_RETRIES', '3')),
}

OUTPUT_CONFIG = {
    'output_excel': os.getenv('OUTPUT_EXCEL_PATH', r'C:\WorkdaySADFeed\Merged_Campaign_Details_March26Final.xlsx'),
    'output_csv': os.getenv('OUTPUT_CSV_PATH', r'C:\WorkdaySADFeed\Merged_Campaign_Details_March26Final.csv'),
}

LOGGING_CONFIG = {
    "level": os.getenv("LOG_LEVEL", "INFO").upper(),
    "to_file": os.getenv("LOG_TO_FILE", "false").lower() == "true",
    "file_path": os.getenv("LOG_FILE_PATH", ""),
    "max_bytes": int(os.getenv("LOG_MAX_BYTES", "5242880")),
    "backup_count": int(os.getenv("LOG_BACKUP_COUNT", "5")),
    "use_utc": os.getenv("LOG_USE_UTC", "false").lower() == "true",
}

# ── Splunk config ─────────────────────────────────────────────────────────────
SPLUNK_HOST         = "https://lilly-infosec.splunkcloud.com:8089"
SPLUNK_TOKEN        = os.getenv("SPLUNK_API_KEY")
SPLUNK_HEADERS      = {
    "Authorization": f"Splunk {SPLUNK_TOKEN}",
    "Content-Type":  "application/x-www-form-urlencoded",
}
SPLUNK_CAMPAIGN_EARLIEST = "2026-03-02T00:00:00"
SPLUNK_CAMPAIGN_LATEST   = "2026-03-09T23:59:59"
TIME_WINDOW_MINUTES      = 1440   # ±24 hours
SPLUNK_BATCH_SIZE        = 500
SPLUNK_SUBMIT_DELAY      = 3
SPLUNK_MAX_RETRIES       = 5
SPLUNK_RETRY_DELAY       = 10
SPLUNK_INITIAL_POLL      = 5
SPLUNK_RETRY_JOB_DELAY   = 3

PROOFPOINT_FIELDS = [
    'Email Address', 'First Name', 'Last Name', 'Campaign Guid', 'Users Guid',
    'Campaign Title', 'Phishing Template', 'Date Sent', 'Primary Email Opened',
    'Date Email Opened', 'Multi Email Open', 'Email Opened IP Address',
    'Email Opened Browser', 'Email Opened Browser Version', 'Email Opened OS',
    'Email Opened OS Version', 'Primary Clicked', 'Date Clicked', 'Multi Click Event',
    'Clicked IP Address', 'Clicked Browser', 'Clicked Browser Version', 'Clicked OS',
    'Clicked OS Version', 'Primary Compromised Login', 'Date Login Compromised',
    'Multi Compromised', 'Primary Attachment Open', 'Date Attachment Open',
    'Multi Attachment Open', 'Reported', 'Date Reported', 'Passed?', 'Whois ISP',
    'Whois Country', 'Teachable Moment Started', 'Acknowledgement Completed',
    'False Positive',
]

WORKDAY_FIELDS = [
    'Level5SupervioryOrganizationid', 'Level5SupervioryOrganizationdesc',
    'Level6SupervioryOrganizationid', 'Level6SupervioryOrganizationdesc',
    'Level3SupervioryOrganizationid', 'Level3SupervioryOrganizationdesc',
    'Level4SupervioryOrganizationid', 'Level4SupervioryOrganizationdesc',
    'WorkdayEmployeeType', 'TerminationDate', 'ReHireDate', 'HireDate',
    'InternetEmailAddress', 'StatusCode', 'GlobalId', 'SystemLogonId',
    'StatusDescription', 'Title', 'WorkCountryDescription', 'SupervisorGlobalId',
    'OnboardDate', 'RetirementDate', 'SupervisorEmail', 'SupervisorSystemId',
    'JobSubFunctionCode', 'JobSubFunctionDescription',
]

# ============================================
# LOGGING SETUP
# ============================================

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("campaign_merge")
    logger.setLevel(getattr(logging, LOGGING_CONFIG["level"], logging.INFO))
    logger.propagate = False
    if logger.handlers:
        return logger
    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if LOGGING_CONFIG["use_utc"]:
        formatter.converter = time.gmtime
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logger.level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    if LOGGING_CONFIG["to_file"]:
        file_path = LOGGING_CONFIG["file_path"].strip()
        if not file_path:
            out_dir = os.path.dirname(OUTPUT_CONFIG["output_excel"])
            file_path = os.path.join(out_dir, "logs", "campaign_merge.log")
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        file_handler = RotatingFileHandler(
            file_path, maxBytes=LOGGING_CONFIG["max_bytes"],
            backupCount=LOGGING_CONFIG["backup_count"], encoding="utf-8",
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
    if not timestamp_str or pd.isna(timestamp_str):
        return None
    try:
        if isinstance(timestamp_str, str):
            timestamp_str = timestamp_str.replace('Z', '+00:00')
        return pd.to_datetime(timestamp_str)
    except Exception as e:
        logger.warning("Failed to parse timestamp '%s': %s", timestamp_str, e)
        return None


def is_false_positive(date_sent, date_clicked, whois_isp):
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
        logger.info("False positive detected. Sent=%s Clicked=%s Delta=%.2fs ISP=%s",
                    date_sent, date_clicked, time_diff, whois_isp)
    return is_fp


def add_executive_leadership_column(df):
    if 'JobSubFunctionCode' in df.columns:
        df['Executive Leadership'] = df['JobSubFunctionCode'].apply(
            lambda x: True if pd.notna(x) and str(x).strip() == 'JFA000011' else False
        )
        logger.info("Executive Leadership column added. Executives=%d", int(df['Executive Leadership'].sum()))
    else:
        df['Executive Leadership'] = False
        logger.warning("'JobSubFunctionCode' not found. Executive Leadership set to False.")
    return df

# ============================================
# WORKDAY API
# ============================================

def get_workday_access_token():
    logger.info("Requesting Workday access token...")
    data = {
        'grant_type': 'client_credentials',
        'client_id': WORKDAY_CONFIG['client_id'],
        'client_secret': WORKDAY_CONFIG['client_secret'],
        'scope': WORKDAY_CONFIG['scope'],
    }
    response = requests.post(WORKDAY_CONFIG['token_url'], data=data,
                             headers={'Content-Type': 'application/x-www-form-urlencoded'})
    response.raise_for_status()
    logger.info("Workday token acquired.")
    return response.json()['access_token']


def fetch_workday_workers():
    logger.info("Fetching Workday workers...")
    access_token = get_workday_access_token()
    headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
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
        url = (f"{WORKDAY_CONFIG['api_url']}?{filter_query}"
               f"&$select={select_fields}&$top={page_size}&$skip={skip}")
        try:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.raise_for_status()
            records = resp.json().get('value', [])
            if not records:
                break
            all_records.extend(records)
            logger.info("Retrieved %d Workday records (total=%d).", len(records), len(all_records))
            skip += page_size
        except requests.exceptions.RequestException as e:
            logger.error("Workday fetch failed: %s", e)
            break
    logger.info("Total Workday records: %d", len(all_records))
    return all_records

# ============================================
# PROOFPOINT API
# ============================================

def fetch_proofpoint_records():
    logger.info("Fetching Proofpoint data...")
    all_records = []
    page_number = 1
    has_more_pages = True
    expected_total = None
    headers = {'x-apikey-token': PROOFPOINT_CONFIG['api_key']}
    while has_more_pages:
        params = {
            'page[number]': page_number,
            'page[size]': PROOFPOINT_CONFIG['page_size'],
            'filter[_campaignstartdate_start]': PROOFPOINT_CONFIG['start_date'],
            'filter[_campaignstartdate_end]': PROOFPOINT_CONFIG['end_date'],
            'filter[_includenoaction]': 'TRUE',
            'filter[_includedeletedusers]': 'TRUE',
        }
        retry_count = 0
        success = False
        while retry_count < PROOFPOINT_CONFIG['max_retries'] and not success:
            try:
                if page_number > 1 or retry_count > 0:
                    time.sleep(PROOFPOINT_CONFIG['rate_limit_delay'])
                resp = requests.get(PROOFPOINT_CONFIG['base_url'], headers=headers,
                                    params=params, timeout=30,
                                    verify=PROOFPOINT_CONFIG['verify_ssl'])
                if resp.status_code == 429:
                    retry_count += 1
                    time.sleep(int(resp.headers.get('Retry-After', PROOFPOINT_CONFIG['retry_delay'])))
                    continue
                if resp.status_code == 504:
                    retry_count += 1
                    time.sleep(PROOFPOINT_CONFIG['retry_delay'] * retry_count)
                    continue
                resp.raise_for_status()
                data = resp.json()
                if expected_total is None:
                    expected_total = data.get('meta', {}).get('count')
                    if expected_total:
                        logger.info("Proofpoint total count: %s", expected_total)
                if data.get('data'):
                    all_records.extend(data['data'])
                    logger.info("Page %d: %d records (total=%d).", page_number, len(data['data']), len(all_records))
                    page_number += 1
                    success = True
                else:
                    has_more_pages = False
                    success = True
            except requests.exceptions.RequestException as e:
                logger.error("Proofpoint fetch error: %s", e)
                retry_count += 1
                if retry_count >= PROOFPOINT_CONFIG['max_retries']:
                    has_more_pages = False
                    success = True
                else:
                    time.sleep(PROOFPOINT_CONFIG['retry_delay'])
        if retry_count >= PROOFPOINT_CONFIG['max_retries']:
            has_more_pages = False
    logger.info("Total Proofpoint records: %d", len(all_records))
    if expected_total and len(all_records) < int(expected_total):
        logger.warning("Expected %s but fetched %d.", expected_total, len(all_records))
    return all_records


def transform_proofpoint_data(records):
    logger.info("Transforming Proofpoint data...")
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
        email_views       = [e for e in events_sorted if e['attributes']['eventtype'] == 'Email View']
        email_clicks      = [e for e in events_sorted if e['attributes']['eventtype'] == 'Email Click']
        data_submissions  = [e for e in events_sorted if e['attributes']['eventtype'] == 'Data Submission']
        attachment_opens  = [e for e in events_sorted if e['attributes']['eventtype'] == 'Attachment Open']
        tm_sent           = [e for e in events_sorted if e['attributes']['eventtype'] == 'TM Sent']
        tm_complete       = [e for e in events_sorted if e['attributes']['eventtype'] == 'TM Complete']
        reported          = [e for e in events_sorted if e['attributes']['eventtype'] == 'Reported']

        campaign_type = first_event.get('campaigntype', '')
        if campaign_type == 'Drive By':
            failure_condition = len(email_clicks) > 0
        elif campaign_type == 'Data Entry Campaign':
            failure_condition = len(data_submissions) > 0
        elif campaign_type == 'Attachment':
            failure_condition = len(attachment_opens) > 0
        else:
            failure_condition = False

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

        date_sent    = first_event.get('senttimestamp')
        date_clicked = get_first_attr(email_clicks, 'eventtimestamp')
        whois_isp    = whois_source.get('whois_isp')
        primary_clicked = len(email_clicks) > 0

        is_fp = is_false_positive(date_sent, date_clicked, whois_isp)
        if is_fp:
            primary_clicked = False
            false_positive_count += 1

        transformed_data.append({
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
        })

    logger.info("Transformed %d records. False positives: %d", len(transformed_data), false_positive_count)
    return transformed_data

# ============================================
# SPLUNK OS LOOKUP
# ============================================

def _splunk_parse_iso(ts):
    if not ts or not str(ts).strip():
        return None
    ts = str(ts).strip().rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d",
                "%m/%d/%Y %H:%M:%S", "%m/%d/%Y"):
        try:
            from datetime import datetime
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _splunk_time(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def _normalize_os(val):
    if not val or not str(val).strip():
        return val
    v = str(val).strip().lower()
    if v.startswith("ios"):
        return "Ios"
    if v.startswith("windows"):
        return "Windows"
    if v.startswith("mac") or v.startswith("macos") or v.startswith("os x"):
        return "Mac OS"
    return val


def _resolve_anchor(row_dict):
    """Returns (timestamp_str, source) — 'no_action' if user took no action."""
    reported     = str(row_dict.get("Reported") or "").strip().upper()
    date_rep     = str(row_dict.get("Date Reported") or "").strip()
    date_clicked = str(row_dict.get("Date Clicked") or "").strip()
    date_opened  = str(row_dict.get("Date Email Opened") or "").strip()
    if reported == "TRUE" and date_rep:
        return date_rep, "date_reported"
    elif date_clicked:
        return date_clicked, "date_clicked"
    elif date_opened:
        return date_opened, "date_email_opened"
    return "", "no_action"


def _closest_match(candidates, anchor_dt):
    from datetime import timedelta
    if not candidates:
        return None
    if anchor_dt is None:
        return max(candidates, key=lambda c: c["dt"])
    window = timedelta(minutes=TIME_WINDOW_MINUTES)
    in_window = [c for c in candidates if abs(c["dt"] - anchor_dt) <= window]
    pool = in_window if in_window else candidates
    return min(pool, key=lambda c: abs(c["dt"] - anchor_dt))


def _submit_job(query, earliest, latest):
    resp = requests.post(
        f"{SPLUNK_HOST}/services/search/jobs",
        headers=SPLUNK_HEADERS,
        data={"search": query, "output_mode": "json",
              "earliest_time": earliest, "latest_time": latest},
        verify=False, timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["sid"]


def _poll_and_fetch(sid):
    url = f"{SPLUNK_HOST}/services/search/jobs/{sid}"
    time.sleep(SPLUNK_INITIAL_POLL)
    while True:
        resp = requests.get(url, headers=SPLUNK_HEADERS,
                            params={"output_mode": "json"}, verify=False, timeout=30)
        resp.raise_for_status()
        state = resp.json()["entry"][0]["content"]["dispatchState"]
        if state == "DONE":
            break
        elif state == "FAILED":
            raise RuntimeError(f"Splunk job {sid} FAILED")
        time.sleep(5)
    resp = requests.get(
        f"{SPLUNK_HOST}/services/search/jobs/{sid}/results",
        headers=SPLUNK_HEADERS, params={"output_mode": "json", "count": 0},
        verify=False, timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get("results", [])


def _run_batches(batch_specs):
    raw = defaultdict(list)
    total = len(batch_specs)
    for idx, (query, earliest, latest, label) in enumerate(batch_specs, 1):
        for attempt in range(1, SPLUNK_MAX_RETRIES + 1):
            try:
                sid  = _submit_job(query, earliest, latest)
                rows = _poll_and_fetch(sid)
                for r in rows:
                    k = (r.get("userIdentity") or "").strip().lower()
                    if k:
                        raw[k].append(r)
                logger.info("Splunk %d/%d done — %d users so far", idx, total, len(raw))
                time.sleep(SPLUNK_SUBMIT_DELAY)
                break
            except Exception as exc:
                wait = SPLUNK_RETRY_DELAY * (2 ** (attempt - 1))
                logger.warning("%s attempt %d/%d: %s — retry in %ds",
                               label, attempt, SPLUNK_MAX_RETRIES, exc, wait)
                time.sleep(wait)
                if attempt == SPLUNK_MAX_RETRIES:
                    logger.error("%s failed after %d attempts — skipping.", label, SPLUNK_MAX_RETRIES)
    return dict(raw)


def _azuread_query(emails, earliest, latest):
    ef = " OR ".join(f'"{e}"' for e in emails)
    el = ", ".join(f'"{e.lower()}"' for e in emails)
    q = f"""
search index="lilly_infosec_azuread_diagnostics" category=SignInLogs resultSignature=SUCCESS ({ef})
| rename properties.userPrincipalName as userIdentity
| rename properties.deviceDetail.operatingSystem as splunk_os
| rename properties.deviceDetail.operatingSystemVersion as splunk_os_version
| where lower(userIdentity) IN ({el})
| where isnotnull(splunk_os) AND splunk_os != "" AND lower(splunk_os) != "null"
| eval ts = strftime(_time, "%Y-%m-%dT%H:%M:%S")
| sort 0 - _time
| table ts, userIdentity, callerIpAddress, splunk_os, splunk_os_version
""".strip()
    return q, earliest, latest


def _proofpoint_splunk_query(emails):
    ef = " OR ".join(f'"{e}"' for e in emails)
    el = ", ".join(f'"{e.lower()}"' for e in emails)
    q = f"""
search index="lilly_infosec_proofpoint_education" ({ef})
| rename attributes.useremailaddress as userIdentity
| rename attributes.os               as pf_os
| rename attributes.os_version       as pf_os_version
| rename attributes.ip_address       as pf_ip
| rename attributes.eventtype        as eventtype
| where lower(userIdentity) IN ({el})
| where isnotnull(pf_os) AND pf_os != "" AND lower(pf_os) != "null"
| where eventtype IN ("Email Click","Email View","Reported","TM Sent","Data Submission")
| eval ts = strftime(_time, "%Y-%m-%dT%H:%M:%S")
| sort 0 - _time
| table ts, userIdentity, pf_os, pf_os_version, pf_ip, eventtype
""".strip()
    return q, SPLUNK_CAMPAIGN_EARLIEST, SPLUNK_CAMPAIGN_LATEST


def _parse_azuread(raw):
    out = {}
    for email, rows in raw.items():
        parsed = []
        for r in rows:
            dt     = _splunk_parse_iso(r.get("ts") or r.get("_time") or "")
            os_val = (r.get("splunk_os") or "").strip()
            if not dt or not os_val or os_val.lower() == "null":
                continue
            parsed.append({"dt": dt, "os": _normalize_os(os_val),
                           "os_version": r.get("splunk_os_version", ""),
                           "ip": r.get("callerIpAddress", ""),
                           "ts": r.get("ts") or r.get("_time") or ""})
        if parsed:
            out[email] = parsed
    return out


def _parse_proofpoint_splunk(raw):
    out = {}
    for email, rows in raw.items():
        parsed = []
        for r in rows:
            dt     = _splunk_parse_iso(r.get("ts") or r.get("_time") or "")
            os_val = (r.get("pf_os") or "").strip()
            if not dt or not os_val or os_val.lower() == "null":
                continue
            parsed.append({"dt": dt, "os": _normalize_os(os_val),
                           "os_version": r.get("pf_os_version", ""),
                           "ip": r.get("pf_ip", ""),
                           "ts": r.get("ts") or r.get("_time") or "",
                           "eventtype": r.get("eventtype", "")})
        if parsed:
            out[email] = parsed
    return out


def _retry_single(unresolved_emails):
    """Single-email AzureAD queries for still-unresolved users."""
    results = {}
    total = len(unresolved_emails)
    logger.info("Phase 3: single-email retry for %d users...", total)
    for idx, email in enumerate(unresolved_emails, 1):
        ef = email
        q = f"""
search index="lilly_infosec_azuread_diagnostics" category=SignInLogs resultSignature=SUCCESS "{ef}"
| rename properties.userPrincipalName as userIdentity
| rename properties.deviceDetail.operatingSystem as splunk_os
| rename properties.deviceDetail.operatingSystemVersion as splunk_os_version
| where lower(userIdentity) = lower("{ef}")
| where isnotnull(splunk_os) AND splunk_os != "" AND lower(splunk_os) != "null"
| eval ts = strftime(_time, "%Y-%m-%dT%H:%M:%S")
| sort 0 - _time
| table ts, userIdentity, callerIpAddress, splunk_os, splunk_os_version
""".strip()
        try:
            sid  = _submit_job(q, SPLUNK_CAMPAIGN_EARLIEST, SPLUNK_CAMPAIGN_LATEST)
            rows = _poll_and_fetch(sid)
            if rows:
                r      = rows[0]
                os_val = _normalize_os((r.get("splunk_os") or "").strip())
                if os_val and os_val.lower() != "null":
                    results[email] = {"os": os_val,
                                      "os_version": r.get("splunk_os_version", ""),
                                      "ip": r.get("callerIpAddress", ""),
                                      "ts": r.get("ts", ""),
                                      "ts_source": "retry→azuread"}
                    logger.info("[%d/%d] %s ✓ %s", idx, total, email, os_val)
                else:
                    logger.info("[%d/%d] %s – no OS found", idx, total, email)
            else:
                logger.info("[%d/%d] %s – no results", idx, total, email)
        except Exception as exc:
            logger.warning("[%d/%d] %s WARN: %s", idx, total, email, exc)
        time.sleep(SPLUNK_RETRY_JOB_DELAY)
    return results


def enrich_with_splunk_os(merged_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add splunk_os, splunk_os_version, splunk_ip, splunk_ts, splunk_ts_source
    columns to the merged DataFrame using the 3-phase Splunk lookup.
    No-action users (no Date Reported / Clicked / Opened) are skipped.
    """
    from datetime import timedelta

    logger.info("Starting Splunk OS enrichment for %d merged records...", len(merged_df))

    rows = merged_df.to_dict("records")

    # Pre-compute anchors
    for row in rows:
        ts_str, source    = _resolve_anchor(row)
        row["_ts_str"]    = ts_str
        row["_ts_source"] = source
        row["_anchor_dt"] = _splunk_parse_iso(ts_str)

    active_emails = list(dict.fromkeys(
        str(row.get("Email Address") or "").strip().lower()
        for row in rows
        if str(row.get("Email Address") or "").strip()
        and row["_ts_source"] != "no_action"
    ))
    logger.info("%d active users — %d no-action users skipped.",
                len(active_emails), len(rows) - len(active_emails))

    # Phase 1: Proofpoint
    logger.info("Phase 1 — Proofpoint for %d active users...", len(active_emails))
    pf_specs = []
    for i in range(0, len(active_emails), SPLUNK_BATCH_SIZE):
        batch = active_emails[i:i+SPLUNK_BATCH_SIZE]
        q, e, l = _proofpoint_splunk_query(batch)
        pf_specs.append((q, e, l, f"Proofpoint-{i}"))
    pf_raw     = _run_batches(pf_specs)
    proofpoint = _parse_proofpoint_splunk(pf_raw)
    logger.info("Phase 1 resolved %d users.", len(proofpoint))

    # Phase 2: AzureAD batch
    missing = [e for e in active_emails if e not in proofpoint]
    logger.info("Phase 2 — AzureAD batch for %d users...", len(missing))

    email_windows = {}
    date_buckets  = defaultdict(list)
    for row in rows:
        email = str(row.get("Email Address") or "").strip().lower()
        if email not in missing:
            continue
        anchor = row["_anchor_dt"]
        if anchor:
            e      = _splunk_time(anchor - timedelta(minutes=TIME_WINDOW_MINUTES))
            l      = _splunk_time(anchor + timedelta(minutes=TIME_WINDOW_MINUTES))
            bucket = anchor.strftime("%Y-%m-%d")
        else:
            e, l   = SPLUNK_CAMPAIGN_EARLIEST, SPLUNK_CAMPAIGN_LATEST
            bucket = "no_anchor"
        email_windows[email] = (e, l)
        date_buckets[bucket].append(email)

    for k in date_buckets:
        date_buckets[k] = list(dict.fromkeys(date_buckets[k]))

    az_specs = []
    for bucket, bemails in date_buckets.items():
        windows  = [email_windows[e] for e in bemails]
        earliest = min(w[0] for w in windows)
        latest   = max(w[1] for w in windows)
        for i in range(0, len(bemails), SPLUNK_BATCH_SIZE):
            batch = bemails[i:i+SPLUNK_BATCH_SIZE]
            q, e, l = _azuread_query(batch, earliest, latest)
            az_specs.append((q, e, l, f"AzureAD-{bucket}-{i}"))

    az_raw  = _run_batches(az_specs)
    azuread = _parse_azuread(az_raw)
    logger.info("Phase 2 resolved %d users.", len(azuread))

    # Phase 3: single-email retry
    still_missing = [e for e in active_emails if e not in proofpoint and e not in azuread]
    retry_results = _retry_single(still_missing)
    logger.info("Phase 3 resolved %d users.", len(retry_results))

    # Assemble OS columns
    splunk_cols = ["splunk_lookup_timestamp", "splunk_ts_source",
                   "splunk_os", "splunk_os_version", "splunk_ip", "splunk_ts"]
    for col in splunk_cols:
        merged_df[col] = ""

    for i, row in enumerate(rows):
        email     = str(row.get("Email Address") or "").strip().lower()
        src       = row["_ts_source"]
        anchor_dt = row["_anchor_dt"]
        os_info   = {"splunk_os": "", "splunk_os_version": "",
                     "splunk_ip": "", "splunk_ts": "", "splunk_ts_source": ""}

        if src != "no_action":
            pf_match = _closest_match(proofpoint.get(email, []), anchor_dt)
            if pf_match:
                os_info = {"splunk_os":         pf_match["os"],
                           "splunk_os_version": pf_match["os_version"],
                           "splunk_ip":         pf_match["ip"],
                           "splunk_ts":         pf_match["ts"],
                           "splunk_ts_source":  f"proofpoint({pf_match['eventtype']})"}
            elif azuread.get(email):
                az_match = _closest_match(azuread[email], anchor_dt)
                if az_match:
                    os_info = {"splunk_os":         az_match["os"],
                               "splunk_os_version": az_match["os_version"],
                               "splunk_ip":         az_match["ip"],
                               "splunk_ts":         az_match["ts"],
                               "splunk_ts_source":  src + "→azuread"}
            elif email in retry_results:
                r = retry_results[email]
                os_info = {"splunk_os":         r["os"],
                           "splunk_os_version": r["os_version"],
                           "splunk_ip":         r["ip"],
                           "splunk_ts":         r["ts"],
                           "splunk_ts_source":  r["ts_source"]}

        merged_df.at[i, "splunk_lookup_timestamp"] = row["_ts_str"]
        merged_df.at[i, "splunk_ts_source"]        = os_info["splunk_ts_source"]
        merged_df.at[i, "splunk_os"]               = os_info["splunk_os"]
        merged_df.at[i, "splunk_os_version"]       = os_info["splunk_os_version"]
        merged_df.at[i, "splunk_ip"]               = os_info["splunk_ip"]
        merged_df.at[i, "splunk_ts"]               = os_info["splunk_ts"]

    resolved  = int((merged_df["splunk_os"] != "").sum())
    no_action = int((merged_df["splunk_ts_source"] == "").sum())
    logger.info("Splunk enrichment complete. Resolved=%d No-action=%d Unresolved=%d",
                resolved, no_action, len(merged_df) - resolved - no_action)

    return merged_df

# ============================================
# MERGE AND EXPORT
# ============================================

def merge_datasets(proofpoint_df, workday_df):
    logger.info("Merging Proofpoint and Workday datasets...")
    proofpoint_df_filtered = proofpoint_df[PROOFPOINT_FIELDS].copy()
    workday_df = add_executive_leadership_column(workday_df)
    workday_fields_with_exec = WORKDAY_FIELDS + ['Executive Leadership']
    workday_df_filtered = workday_df[workday_fields_with_exec].copy()
    proofpoint_df_filtered['Email Address'] = proofpoint_df_filtered['Email Address'].str.lower().str.strip()
    workday_df_filtered['InternetEmailAddress'] = workday_df_filtered['InternetEmailAddress'].str.lower().str.strip()
    merged_df = pd.merge(
        proofpoint_df_filtered, workday_df_filtered,
        left_on='Email Address', right_on='InternetEmailAddress',
        how='left', suffixes=('_Proofpoint', '_Workday'),
    )
    if 'InternetEmailAddress' in merged_df.columns:
        merged_df = merged_df.drop(columns=['InternetEmailAddress'])
    logger.info("Merged: %d records. Matched=%d Unmatched=%d",
                len(merged_df), int(merged_df['GlobalId'].notna().sum()),
                int(merged_df['GlobalId'].isna().sum()))
    return merged_df


def export_to_excel_with_sheets(workday_df, proofpoint_df, merged_df, output_path):
    logger.info("Exporting to Excel (3 sheets)...")
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            workday_df.to_excel(writer, sheet_name='Workday Feed', index=False)
            proofpoint_df.to_excel(writer, sheet_name='Proofpoint Data', index=False)
            merged_df.to_excel(writer, sheet_name='Merged Data', index=False)
            for sheet_name in writer.sheets:
                ws = writer.sheets[sheet_name]
                for column in ws.columns:
                    max_length = max((len(str(cell.value or "")) for cell in column), default=10)
                    ws.column_dimensions[column[0].column_letter].width = min(max_length + 2, 50)
                ws.freeze_panes = 'A2'
        logger.info("Excel saved: %s", output_path)
    except Exception as e:
        logger.exception("Failed to write Excel: %s", e)
        csv_path = output_path.replace('.xlsx', '_merged.csv')
        merged_df.to_csv(csv_path, index=False, encoding='utf-8')
        logger.info("Fallback CSV saved: %s", csv_path)


def export_merged_to_csv(merged_df, output_csv_path):
    try:
        os.makedirs(os.path.dirname(output_csv_path), exist_ok=True)
        merged_df.to_csv(output_csv_path, index=False, encoding='utf-8')
        logger.info("Merged CSV saved: %s", output_csv_path)
    except Exception as e:
        logger.exception("Failed to write merged CSV: %s", e)
        raise

# ============================================
# MAIN
# ============================================

def main():
    logger.info("=" * 70)
    logger.info("MERGED PROOFPOINT + WORKDAY + SPLUNK OS CAMPAIGN EXPORT")
    logger.info("=" * 70)

    try:
        # Step 1: Workday
        workday_records = fetch_workday_workers()
        workday_df = pd.DataFrame(workday_records)
        if workday_df.empty:
            workday_df = pd.DataFrame(columns=WORKDAY_FIELDS + ['Executive Leadership'])
        else:
            workday_df = workday_df[workday_df['InternetEmailAddress'].notna()]
            workday_df = workday_df[workday_df['InternetEmailAddress'].str.strip() != '']
            workday_df = add_executive_leadership_column(workday_df)

        # Step 2: Proofpoint
        proofpoint_records = fetch_proofpoint_records()
        if not proofpoint_records:
            logger.error("No Proofpoint records returned. Exiting.")
            sys.exit(1)

        # Step 3: Transform Proofpoint
        proofpoint_df = pd.DataFrame(transform_proofpoint_data(proofpoint_records))

        # Step 4: Merge
        merged_df = merge_datasets(proofpoint_df, workday_df)

        # Step 5: Splunk OS enrichment (merged CSV only)
        merged_df = enrich_with_splunk_os(merged_df)

        # Step 6: Export Excel (merged sheet includes Splunk OS columns)
        export_to_excel_with_sheets(workday_df, proofpoint_df, merged_df,
                                    OUTPUT_CONFIG['output_excel'])

        # Step 7: Export merged CSV
        export_merged_to_csv(merged_df, OUTPUT_CONFIG['output_csv'])

        logger.info("=" * 70)
        logger.info("EXPORT COMPLETE")
        logger.info("Excel: %s", OUTPUT_CONFIG['output_excel'])
        logger.info("CSV:   %s", OUTPUT_CONFIG['output_csv'])
        logger.info("=" * 70)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()