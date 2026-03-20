import os
import sys
import time
import ssl
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict
from datetime import datetime, timedelta

import requests
import urllib3
import pandas as pd
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

# ── SSL Fix for Lilly corporate proxy ────────────────────────────────────────
# Forces TLS 1.2 and disables cert verification to bypass proxy interception.

class _ForceTLS12Adapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname  = False
        ctx.verify_mode     = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        kwargs['ssl_context'] = ctx
        super().init_poolmanager(*args, **kwargs)

def _make_session() -> requests.Session:
    s = requests.Session()
    s.mount('https://', _ForceTLS12Adapter())
    return s

SESSION = _make_session()
VERIFY  = False

# ============================================
# CONFIGURATION
# ============================================

WORKDAY_CONFIG = {
    'client_id':           os.getenv('WORKDAY_CLIENT_ID'),
    'client_secret':       os.getenv('WORKDAY_CLIENT_SECRET'),
    'token_url':           os.getenv('WORKDAY_TOKEN_URL'),
    'api_url':             os.getenv('WORKDAY_API_URL'),
    'scope':               os.getenv('WORKDAY_SCOPE'),
    'campaign_start_date': os.getenv('CAMPAIGN_START_DATE', '2026-03-02'),
}

PROOFPOINT_CONFIG = {
    'base_url':          os.getenv('PROOFPOINT_BASE_URL'),
    'api_key':           os.getenv('PROOFPOINT_API_KEY'),
    'start_date':        os.getenv('PROOFPOINT_START_DATE', '2026-03-02'),
    'end_date':          os.getenv('PROOFPOINT_END_DATE', '2026-03-09'),
    'page_size':         int(os.getenv('PROOFPOINT_PAGE_SIZE', '500')),
    'verify_ssl':        os.getenv('PROOFPOINT_VERIFY_SSL', 'False').lower() == 'true',
    'rate_limit_delay':  float(os.getenv('PROOFPOINT_RATE_LIMIT_DELAY', '1.0')),
    'retry_delay':       float(os.getenv('PROOFPOINT_RETRY_DELAY', '5.0')),
    'max_retries':       int(os.getenv('PROOFPOINT_MAX_RETRIES', '3')),
}

OUTPUT_CONFIG = {
    'output_excel': os.getenv('OUTPUT_EXCEL_PATH', r'C:\WorkdaySADFeed\Merged_Campaign_Details_March26Final.xlsx'),
    'output_csv':   os.getenv('OUTPUT_CSV_PATH',   r'C:\WorkdaySADFeed\Merged_Campaign_Details_March26Final.csv'),
}

LOGGING_CONFIG = {
    'level':        os.getenv('LOG_LEVEL', 'INFO').upper(),
    'to_file':      os.getenv('LOG_TO_FILE', 'false').lower() == 'true',
    'file_path':    os.getenv('LOG_FILE_PATH', ''),
    'max_bytes':    int(os.getenv('LOG_MAX_BYTES', '5242880')),
    'backup_count': int(os.getenv('LOG_BACKUP_COUNT', '5')),
    'use_utc':      os.getenv('LOG_USE_UTC', 'false').lower() == 'true',
}

# ── Splunk config ─────────────────────────────────────────────────────────────
SPLUNK_HOST              = os.getenv('SPLUNK_HOST', 'https://lilly-infosec.splunkcloud.com:8089')
SPLUNK_TOKEN             = os.getenv('SPLUNK_API_KEY')
SPLUNK_HEADERS           = {
    'Authorization': f'Splunk {SPLUNK_TOKEN}',
    'Content-Type':  'application/x-www-form-urlencoded',
}
SPLUNK_CAMPAIGN_EARLIEST = os.getenv('SPLUNK_CAMPAIGN_EARLIEST', '2026-01-20T00:00:00')
SPLUNK_CAMPAIGN_LATEST   = os.getenv('SPLUNK_CAMPAIGN_LATEST',   '2026-01-27T23:59:59')
TIME_WINDOW_MINUTES      = int(os.getenv('SPLUNK_TIME_WINDOW_MINUTES', '1440'))
SPLUNK_BATCH_SIZE        = int(os.getenv('SPLUNK_BATCH_SIZE', '500'))
SPLUNK_SUBMIT_DELAY      = float(os.getenv('SPLUNK_SUBMIT_DELAY', '3'))
SPLUNK_MAX_RETRIES       = int(os.getenv('SPLUNK_MAX_RETRIES', '5'))
SPLUNK_RETRY_DELAY       = float(os.getenv('SPLUNK_RETRY_DELAY', '10'))
SPLUNK_INITIAL_POLL      = float(os.getenv('SPLUNK_INITIAL_POLL', '5'))
SPLUNK_RETRY_JOB_DELAY   = float(os.getenv('SPLUNK_RETRY_JOB_DELAY', '3'))
SPLUNK_JOB_TIMEOUT       = int(os.getenv('SPLUNK_JOB_TIMEOUT', '600'))

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

# Added PayGradeLevelCode, PayGradeLevelDescription, FirstName, LastName
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
    'PayGradeLevelCode', 'PayGradeLevelDescription',
    'FirstName', 'LastName',                                                # NEW
]

# ============================================
# LOGGING SETUP
# ============================================

def setup_logging() -> logging.Logger:
    logger = logging.getLogger('campaign_merge')
    logger.setLevel(getattr(logging, LOGGING_CONFIG['level'], logging.INFO))
    logger.propagate = False
    if logger.handlers:
        return logger
    formatter = logging.Formatter(
        fmt='%(asctime)s | %(levelname)s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    if LOGGING_CONFIG['use_utc']:
        formatter.converter = time.gmtime
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logger.level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    if LOGGING_CONFIG['to_file']:
        file_path = LOGGING_CONFIG['file_path'].strip()
        if not file_path:
            out_dir   = os.path.dirname(OUTPUT_CONFIG['output_excel'])
            file_path = os.path.join(out_dir, 'logs', 'campaign_merge.log')
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        file_handler = RotatingFileHandler(
            file_path, maxBytes=LOGGING_CONFIG['max_bytes'],
            backupCount=LOGGING_CONFIG['backup_count'], encoding='utf-8',
        )
        file_handler.setLevel(logger.level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        logger.info('File logging enabled: %s', file_path)
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


def _parse_date(raw: str):
    """Parse a date string to a date object. Raises ValueError on failure."""
    try:
        return datetime.fromisoformat(str(raw).replace('Z', '+00:00')).date()
    except Exception:
        raise ValueError(f"Cannot parse date: '{raw}'")


def is_false_positive(date_sent, date_clicked, whois_isp):
    if not date_sent or not date_clicked or not whois_isp:
        return False
    sent_time    = parse_timestamp(date_sent)
    clicked_time = parse_timestamp(date_clicked)
    if not sent_time or not clicked_time:
        return False
    is_azure  = 'microsoft azure' in str(whois_isp).lower()
    time_diff = abs((clicked_time - sent_time).total_seconds())
    is_fp     = is_azure and time_diff <= 60
    if is_fp:
        logger.info("False positive detected. Sent=%s Clicked=%s Delta=%.2fs ISP=%s",
                    date_sent, date_clicked, time_diff, whois_isp)
    return is_fp


def add_executive_leadership_column(df):
    if 'JobSubFunctionCode' in df.columns:
        df['Executive Leadership'] = df['JobSubFunctionCode'].apply(
            lambda x: True if pd.notna(x) and str(x).strip() == 'JFA000011' else False
        )
        logger.info("Executive Leadership column added. Executives=%d",
                    int(df['Executive Leadership'].sum()))
    else:
        df['Executive Leadership'] = False
        logger.warning("'JobSubFunctionCode' not found. Executive Leadership set to False.")
    return df


def compute_tenure(merged_df: pd.DataFrame, campaign_start_date: str) -> pd.DataFrame:
    """
    Add a 'Tenure' column (in decimal years, rounded to 2 dp) to merged_df.

    Logic:
      - Reference date = campaign_start_date (WORKDAY_CONFIG['campaign_start_date'])
      - Anchor date    = ReHireDate if non-null and parseable, else HireDate
      - Tenure (years) = (reference_date - anchor_date).days / 365.25
      - Negative tenures (hire date after campaign start) are left as-is so
        data anomalies remain visible; consumers can filter them out.
      - Rows where both HireDate and ReHireDate are null/unparseable get None.
    """
    try:
        ref_date = _parse_date(campaign_start_date)
    except ValueError as e:
        logger.warning("compute_tenure: cannot parse campaign_start_date '%s': %s — "
                       "Tenure set to None for all rows.", campaign_start_date, e)
        merged_df['Tenure'] = None
        return merged_df

    def _tenure_for_row(row):
        # Prefer ReHireDate over HireDate
        for col in ('ReHireDate', 'HireDate'):
            raw = row.get(col)
            if raw and not pd.isna(raw) and str(raw).strip():
                try:
                    anchor = _parse_date(str(raw).strip())
                    days   = (ref_date - anchor).days
                    return round(days / 365.25, 2)
                except ValueError:
                    continue
        return None

    merged_df['Tenure'] = merged_df.apply(_tenure_for_row, axis=1)

    resolved   = int(merged_df['Tenure'].notna().sum())
    unresolved = len(merged_df) - resolved
    logger.info("Tenure computed: resolved=%d unresolved=%d (ref_date=%s, "
                "anchor=ReHireDate if set, else HireDate).",
                resolved, unresolved, ref_date)
    return merged_df

# ============================================
# OBFUSCATED EMAIL RESOLUTION
# ============================================

def resolve_obfuscated_emails(proofpoint_df: pd.DataFrame,
                               workday_df: pd.DataFrame) -> pd.DataFrame:
    """
    For every Proofpoint row whose 'Email Address' ends in '@obfuscated.invalid',
    attempt to find a matching Workday record by (FirstName, LastName) and
    replace the placeholder with the real InternetEmailAddress from Workday.
    All other Proofpoint columns remain untouched; the corrected email then
    joins correctly in the subsequent merge step.

    Matching rules:
      - Case-insensitive, whitespace-stripped comparison on both name fields.
      - Exactly ONE Workday match  → replace email, mark resolved.
      - Zero matches               → log warning, leave placeholder.
      - Multiple matches           → log warning, leave placeholder (ambiguous).

    Adds column 'Email Resolved From Obfuscated' (TRUE/FALSE) so downstream
    consumers can identify which rows were resolved this way.
    """
    proofpoint_df = proofpoint_df.copy()
    proofpoint_df['Email Resolved From Obfuscated'] = 'FALSE'

    obfuscated_mask = (
        proofpoint_df['Email Address']
        .str.lower()
        .str.strip()
        .str.endswith('@obfuscated.invalid', na=False)
    )
    obfuscated_rows = proofpoint_df[obfuscated_mask]

    if obfuscated_rows.empty:
        logger.info("No obfuscated email addresses found in Proofpoint data.")
        return proofpoint_df

    logger.info("Obfuscated email resolution: %d rows to process.", len(obfuscated_rows))

    # Build a (first_lower, last_lower) → [email, ...] lookup from Workday.
    # Collecting lists allows ambiguity detection.
    workday_name_map: dict = defaultdict(list)
    for _, wd_row in workday_df.iterrows():
        first = str(wd_row.get('FirstName')  or '').strip().lower()
        last  = str(wd_row.get('LastName')   or '').strip().lower()
        email = str(wd_row.get('InternetEmailAddress') or '').strip()
        if first and last and email:
            workday_name_map[(first, last)].append(email)

    resolved_count  = 0
    ambiguous_count = 0
    notfound_count  = 0

    for idx in obfuscated_rows.index:
        pp_first   = str(proofpoint_df.at[idx, 'First Name'] or '').strip().lower()
        pp_last    = str(proofpoint_df.at[idx, 'Last Name']  or '').strip().lower()
        orig_email = proofpoint_df.at[idx, 'Email Address']

        if not pp_first or not pp_last:
            logger.warning(
                "Row %d: obfuscated email '%s' has blank name fields — cannot resolve.",
                idx, orig_email,
            )
            notfound_count += 1
            continue

        matches = workday_name_map.get((pp_first, pp_last), [])

        if len(matches) == 1:
            resolved_email = matches[0]
            proofpoint_df.at[idx, 'Email Address'] = resolved_email
            proofpoint_df.at[idx, 'Email Resolved From Obfuscated'] = 'TRUE'
            logger.info(
                "Row %d: resolved '%s' → '%s'  (name: %s %s)",
                idx, orig_email, resolved_email,
                pp_first.title(), pp_last.title(),
            )
            resolved_count += 1

        elif len(matches) > 1:
            logger.warning(
                "Row %d: obfuscated email '%s' matches %d Workday records for "
                "'%s %s' — ambiguous, leaving placeholder.",
                idx, orig_email, len(matches),
                pp_first.title(), pp_last.title(),
            )
            ambiguous_count += 1

        else:
            logger.warning(
                "Row %d: obfuscated email '%s' — no Workday record found for "
                "'%s %s' — leaving placeholder.",
                idx, orig_email,
                pp_first.title(), pp_last.title(),
            )
            notfound_count += 1

    logger.info(
        "Obfuscated email resolution complete: resolved=%d ambiguous=%d not_found=%d",
        resolved_count, ambiguous_count, notfound_count,
    )
    return proofpoint_df

# ============================================
# WORKDAY API
# ============================================

def get_workday_access_token():
    logger.info("Requesting Workday access token...")
    response = requests.post(
        WORKDAY_CONFIG['token_url'],
        data={
            'grant_type':    'client_credentials',
            'client_id':     WORKDAY_CONFIG['client_id'],
            'client_secret': WORKDAY_CONFIG['client_secret'],
            'scope':         WORKDAY_CONFIG['scope'],
        },
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    response.raise_for_status()
    logger.info("Workday token acquired.")
    return response.json()['access_token']


def fetch_workday_workers():
    """
    Fetch all active or recently-terminated workers from Workday.
    Pulls WORKDAY_FIELDS including PayGradeLevelCode, PayGradeLevelDescription,
    FirstName, and LastName.
    """
    logger.info("Fetching Workday workers...")
    access_token  = get_workday_access_token()
    headers       = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
    all_records   = []
    page_size     = 1000
    skip          = 0
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
    all_records    = []
    page_number    = 1
    has_more_pages = True
    expected_total = None
    headers        = {'x-apikey-token': PROOFPOINT_CONFIG['api_key']}

    while has_more_pages:
        params = {
            'page[number]':                     page_number,
            'page[size]':                       PROOFPOINT_CONFIG['page_size'],
            'filter[_campaignstartdate_start]': PROOFPOINT_CONFIG['start_date'],
            'filter[_campaignstartdate_end]':   PROOFPOINT_CONFIG['end_date'],
            'filter[_includenoaction]':         'TRUE',
            'filter[_includedeletedusers]':     'TRUE',
        }
        retry_count = 0
        success     = False

        while retry_count < PROOFPOINT_CONFIG['max_retries'] and not success:
            try:
                if page_number > 1 or retry_count > 0:
                    time.sleep(PROOFPOINT_CONFIG['rate_limit_delay'])
                resp = requests.get(
                    PROOFPOINT_CONFIG['base_url'], headers=headers,
                    params=params, timeout=30,
                    verify=PROOFPOINT_CONFIG['verify_ssl'],
                )
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
                    logger.info("Page %d: %d records (total=%d).",
                                page_number, len(data['data']), len(all_records))
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
        grouped[f"{attrs['user_guid']}_{attrs['campaign_guid']}"].append(record)

    transformed_data     = []
    false_positive_count = 0

    for _, events in grouped.items():
        events_sorted    = sorted(events, key=lambda x: x['attributes']['eventtimestamp'])
        first_event      = events_sorted[0]['attributes']
        email_views      = [e for e in events_sorted if e['attributes']['eventtype'] == 'Email View']
        email_clicks     = [e for e in events_sorted if e['attributes']['eventtype'] == 'Email Click']
        data_submissions = [e for e in events_sorted if e['attributes']['eventtype'] == 'Data Submission']
        attachment_opens = [e for e in events_sorted if e['attributes']['eventtype'] == 'Attachment Open']
        tm_sent          = [e for e in events_sorted if e['attributes']['eventtype'] == 'TM Sent']
        tm_complete      = [e for e in events_sorted if e['attributes']['eventtype'] == 'TM Complete']
        reported         = [e for e in events_sorted if e['attributes']['eventtype'] == 'Reported']

        # Hardened campaigntype matching
        campaign_type_raw = (
            events_sorted[0].get('campaigntype')
            or first_event.get('campaigntype', '')
            or ''
        )
        campaign_type = campaign_type_raw.strip().lower()

        logger.debug("campaigntype raw=%r normalised=%r user=%s campaign=%s",
                     campaign_type_raw, campaign_type,
                     first_event.get('useremailaddress'), first_event.get('campaignname'))

        if campaign_type == 'drive by':
            failure_condition = len(email_clicks) > 0
        elif campaign_type in ('data entry campaign', 'data entry'):
            failure_condition = len(data_submissions) > 0
        elif campaign_type == 'attachment':
            failure_condition = len(attachment_opens) > 0
        else:
            failure_condition = (
                len(email_clicks) > 0
                or len(data_submissions) > 0
                or len(attachment_opens) > 0
            )
            if campaign_type:
                logger.warning(
                    "Unrecognised campaigntype=%r for campaign=%r — "
                    "fallback applied (clicks=%d submissions=%d attachments=%d).",
                    campaign_type_raw, first_event.get('campaignname'),
                    len(email_clicks), len(data_submissions), len(attachment_opens),
                )
            else:
                logger.warning("campaigntype missing for user=%s campaign=%r — fallback applied.",
                               first_event.get('useremailaddress'), first_event.get('campaignname'))

        # Whois only from failure events
        if email_clicks:
            whois_source = email_clicks[0]['attributes']
        elif data_submissions:
            whois_source = data_submissions[0]['attributes']
        elif attachment_opens:
            whois_source = attachment_opens[0]['attributes']
        else:
            whois_source = {}

        def get_first_attr(event_list, attr_name):
            return event_list[0]['attributes'].get(attr_name) if event_list else None

        def bool_to_str(condition):
            return 'TRUE' if condition else 'FALSE'

        date_sent       = first_event.get('senttimestamp')
        date_clicked    = get_first_attr(email_clicks, 'eventtimestamp')
        whois_isp       = whois_source.get('whois_isp')
        primary_clicked = len(email_clicks) > 0

        is_fp = is_false_positive(date_sent, date_clicked, whois_isp)
        if is_fp:
            primary_clicked   = False
            failure_condition = False
            false_positive_count += 1

        transformed_data.append({
            'Email Address':                first_event.get('useremailaddress'),
            'First Name':                   first_event.get('userfirstname'),
            'Last Name':                    first_event.get('userlastname'),
            'Campaign Guid':                first_event.get('campaign_guid'),
            'Users Guid':                   first_event.get('user_guid'),
            'Campaign Title':               first_event.get('campaignname'),
            'Phishing Template':            first_event.get('templatename'),
            'Date Sent':                    date_sent,
            'Primary Email Opened':         bool_to_str(len(email_views) > 0),
            'Date Email Opened':            get_first_attr(email_views, 'eventtimestamp'),
            'Multi Email Open':             max(0, len(email_views) - 1),
            'Email Opened IP Address':      get_first_attr(email_views, 'ip_address'),
            'Email Opened Browser':         get_first_attr(email_views, 'browser'),
            'Email Opened Browser Version': get_first_attr(email_views, 'browser_version'),
            'Email Opened OS':              get_first_attr(email_views, 'os'),
            'Email Opened OS Version':      get_first_attr(email_views, 'os_version'),
            'Primary Clicked':              bool_to_str(primary_clicked),
            'Date Clicked':                 date_clicked,
            'Multi Click Event':            max(0, len(email_clicks) - 1),
            'Clicked IP Address':           get_first_attr(email_clicks, 'ip_address'),
            'Clicked Browser':              get_first_attr(email_clicks, 'browser'),
            'Clicked Browser Version':      get_first_attr(email_clicks, 'browser_version'),
            'Clicked OS':                   get_first_attr(email_clicks, 'os'),
            'Clicked OS Version':           get_first_attr(email_clicks, 'os_version'),
            'Primary Compromised Login':    bool_to_str(len(data_submissions) > 0),
            'Date Login Compromised':       get_first_attr(data_submissions, 'eventtimestamp'),
            'Multi Compromised':            max(0, len(data_submissions) - 1),
            'Primary Attachment Open':      bool_to_str(len(attachment_opens) > 0),
            'Date Attachment Open':         get_first_attr(attachment_opens, 'eventtimestamp'),
            'Multi Attachment Open':        max(0, len(attachment_opens) - 1),
            'Reported':                     bool_to_str(len(reported) > 0),
            'Date Reported':                get_first_attr(reported, 'eventtimestamp'),
            'Passed?':                      bool_to_str(not failure_condition),
            'Whois ISP':                    whois_source.get('whois_isp'),
            'Whois Country':                whois_source.get('whois_country'),
            'Teachable Moment Started':     bool_to_str(len(tm_sent) > 0),
            'Acknowledgement Completed':    bool_to_str(len(tm_complete) > 0),
            'False Positive':               bool_to_str(is_fp),
        })

    logger.info("Transformed %d records. False positives: %d",
                len(transformed_data), false_positive_count)
    return transformed_data

# ============================================
# SPLUNK OS LOOKUP
# ============================================

def _splunk_parse_iso(ts):
    if not ts or not str(ts).strip():
        return None
    ts = str(ts).strip().rstrip('Z')
    for fmt in ('%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M', '%Y-%m-%d',
                '%m/%d/%Y %H:%M:%S', '%m/%d/%Y'):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _splunk_time(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%S')


def _normalize_os(os_val: str) -> str:
    """Priority-ordered OS normalisation map. First match wins."""
    if not os_val or not str(os_val).strip():
        return os_val or ''
    os_lower = str(os_val).strip().lower()
    OS_MAP = [
        ('ipados',    'iPadOS'),
        ('ios',       'iOS'),
        ('android',   'Android'),
        ('windows',   'Windows'),
        ('mac os',    'macOS'),
        ('macos',     'macOS'),
        ('darwin',    'macOS'),
        ('linux',     'Linux'),
        ('ubuntu',    'Linux'),
        ('debian',    'Linux'),
        ('fedora',    'Linux'),
        ('centos',    'Linux'),
        ('chrome os', 'ChromeOS'),
        ('chromeos',  'ChromeOS'),
        ('cros',      'ChromeOS'),
    ]
    for keyword, canonical in OS_MAP:
        if os_lower.startswith(keyword) or keyword in os_lower:
            return canonical
    return str(os_val).strip().title()


def _resolve_anchor(row_dict):
    """
    Returns (timestamp_str, source) for the most relevant FAILURE event.
    Only failed/reported users are queried in Splunk.
    Email-opened-only and no-action users return ('', 'no_action').
    """
    reported        = str(row_dict.get('Reported') or '').strip().upper()
    date_rep        = str(row_dict.get('Date Reported') or '').strip()
    date_clicked    = str(row_dict.get('Date Clicked') or '').strip()
    date_login      = str(row_dict.get('Date Login Compromised') or '').strip()
    date_attachment = str(row_dict.get('Date Attachment Open') or '').strip()

    if reported == 'TRUE' and date_rep:
        return date_rep, 'date_reported'
    elif date_clicked:
        return date_clicked, 'date_clicked'
    elif date_login:
        return date_login, 'date_login_compromised'
    elif date_attachment:
        return date_attachment, 'date_attachment_open'
    return '', 'no_action'


def _closest_match(candidates, anchor_dt):
    if not candidates:
        return None
    if anchor_dt is None:
        return max(candidates, key=lambda c: c['dt'])
    window = timedelta(minutes=TIME_WINDOW_MINUTES)
    in_win = [c for c in candidates if abs(c['dt'] - anchor_dt) <= window]
    pool   = in_win if in_win else candidates
    return min(pool, key=lambda c: abs(c['dt'] - anchor_dt))


def _submit_job(query, earliest, latest):
    resp = SESSION.post(
        f"{SPLUNK_HOST}/services/search/jobs",
        headers=SPLUNK_HEADERS,
        data={'search': query, 'output_mode': 'json',
              'earliest_time': earliest, 'latest_time': latest},
        verify=VERIFY, timeout=120,
    )
    resp.raise_for_status()
    return resp.json()['sid']


def _poll_and_fetch(sid):
    """
    Poll until DONE with a hard 10-minute timeout. Auto-cancels on timeout.
    """
    url           = f"{SPLUNK_HOST}/services/search/jobs/{sid}"
    elapsed       = 0
    poll_interval = 5

    time.sleep(SPLUNK_INITIAL_POLL)
    elapsed += SPLUNK_INITIAL_POLL

    while True:
        if elapsed >= SPLUNK_JOB_TIMEOUT:
            logger.warning("Splunk job %s exceeded %ds — cancelling.", sid, SPLUNK_JOB_TIMEOUT)
            try:
                SESSION.delete(url, headers=SPLUNK_HEADERS, verify=VERIFY, timeout=10)
            except Exception:
                pass
            raise RuntimeError(f"Splunk job {sid} timed out after {SPLUNK_JOB_TIMEOUT}s")

        resp = SESSION.get(url, headers=SPLUNK_HEADERS,
                           params={'output_mode': 'json'}, verify=VERIFY, timeout=30)
        resp.raise_for_status()
        state = resp.json()['entry'][0]['content']['dispatchState']

        if state == 'DONE':
            break
        elif state == 'FAILED':
            raise RuntimeError(f"Splunk job {sid} FAILED")

        time.sleep(poll_interval)
        elapsed += poll_interval

    resp = SESSION.get(
        f"{SPLUNK_HOST}/services/search/jobs/{sid}/results",
        headers=SPLUNK_HEADERS,
        params={'output_mode': 'json', 'count': 0},
        verify=VERIFY, timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get('results', [])


def _run_batches(batch_specs):
    raw   = defaultdict(list)
    total = len(batch_specs)
    for idx, (query, earliest, latest, label) in enumerate(batch_specs, 1):
        for attempt in range(1, SPLUNK_MAX_RETRIES + 1):
            try:
                sid  = _submit_job(query, earliest, latest)
                rows = _poll_and_fetch(sid)
                for r in rows:
                    k = (r.get('userIdentity') or '').strip().lower()
                    if k:
                        raw[k].append(r)
                logger.info("Splunk %d/%d done — %d users so far", idx, total, len(raw))
                time.sleep(SPLUNK_SUBMIT_DELAY)
                break
            except Exception as exc:
                wait = SPLUNK_RETRY_DELAY * (2 ** (attempt - 1))
                logger.warning("%s attempt %d/%d: %s — retry in %.0fs",
                               label, attempt, SPLUNK_MAX_RETRIES, exc, wait)
                time.sleep(wait)
                if attempt == SPLUNK_MAX_RETRIES:
                    logger.error("%s failed after %d attempts — skipping.",
                                 label, SPLUNK_MAX_RETRIES)
    return dict(raw)


def _azuread_query(emails, earliest, latest):
    ef = ' OR '.join(f'"{e}"' for e in emails)
    el = ', '.join(f'"{e.lower()}"' for e in emails)
    q  = f"""
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
    """
    Query Proofpoint Splunk index for OS data.
    Only failure-relevant eventtypes — Email Click, Data Submission,
    Attachment Open, Reported. Email View and TM Sent excluded because
    they don't carry meaningful OS data and bloat query volume.
    Scoped to campaign window so Splunk only scans the relevant partition.
    """
    ef = ' OR '.join(f'"{e}"' for e in emails)
    el = ', '.join(f'"{e.lower()}"' for e in emails)
    q  = f"""
search index="lilly_infosec_proofpoint_education" ({ef})
| rename attributes.useremailaddress as userIdentity
| rename attributes.os               as pf_os
| rename attributes.os_version       as pf_os_version
| rename attributes.ip_address       as pf_ip
| rename attributes.eventtype        as eventtype
| where lower(userIdentity) IN ({el})
| where isnotnull(pf_os) AND pf_os != "" AND lower(pf_os) != "null"
| where eventtype IN ("Email Click","Data Submission","Attachment Open","Reported")
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
            dt     = _splunk_parse_iso(r.get('ts') or r.get('_time') or '')
            os_val = (r.get('splunk_os') or '').strip()
            if not dt or not os_val or os_val.lower() == 'null':
                continue
            parsed.append({
                'dt':         dt,
                'os':         _normalize_os(os_val),
                'os_version': r.get('splunk_os_version', ''),
                'ip':         r.get('callerIpAddress', ''),
                'ts':         r.get('ts') or r.get('_time') or '',
            })
        if parsed:
            out[email] = parsed
    return out


def _parse_proofpoint_splunk(raw):
    out = {}
    for email, rows in raw.items():
        parsed = []
        for r in rows:
            dt     = _splunk_parse_iso(r.get('ts') or r.get('_time') or '')
            os_val = (r.get('pf_os') or '').strip()
            if not dt or not os_val or os_val.lower() == 'null':
                continue
            parsed.append({
                'dt':         dt,
                'os':         _normalize_os(os_val),
                'os_version': r.get('pf_os_version', ''),
                'ip':         r.get('pf_ip', ''),
                'ts':         r.get('ts') or r.get('_time') or '',
                'eventtype':  r.get('eventtype', ''),
            })
        if parsed:
            out[email] = parsed
    return out


def _retry_single(unresolved_emails):
    """Phase 3: single-email AzureAD queries for still-unresolved users."""
    results = {}
    total   = len(unresolved_emails)
    logger.info("Phase 3: single-email retry for %d users...", total)
    for idx, email in enumerate(unresolved_emails, 1):
        q = f"""
search index="lilly_infosec_azuread_diagnostics" category=SignInLogs resultSignature=SUCCESS "{email}"
| rename properties.userPrincipalName as userIdentity
| rename properties.deviceDetail.operatingSystem as splunk_os
| rename properties.deviceDetail.operatingSystemVersion as splunk_os_version
| where lower(userIdentity) = lower("{email}")
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
                os_val = _normalize_os((r.get('splunk_os') or '').strip())
                if os_val and os_val.lower() != 'null':
                    results[email] = {
                        'os':         os_val,
                        'os_version': r.get('splunk_os_version', ''),
                        'ip':         r.get('callerIpAddress', ''),
                        'ts':         r.get('ts', ''),
                        'ts_source':  'retry→azuread',
                    }
                    logger.info("[%d/%d] %s ✓ %s", idx, total, email, os_val)
                else:
                    logger.info("[%d/%d] %s — no OS found", idx, total, email)
            else:
                logger.info("[%d/%d] %s — no results", idx, total, email)
        except Exception as exc:
            logger.warning("[%d/%d] %s WARN: %s", idx, total, email, exc)
        time.sleep(SPLUNK_RETRY_JOB_DELAY)
    return results


def enrich_with_splunk_os(merged_df: pd.DataFrame) -> pd.DataFrame:
    """
    Add Splunk OS columns using 3-phase lookup:
      Phase 1 — Proofpoint Splunk (failure events only, campaign-scoped)
      Phase 2 — AzureAD batch (±24h window per user)
      Phase 3 — single-email retry (full campaign window)

    Only failed/reported users are queried. Email-opened-only and
    no-action users are skipped entirely — they have no OS data in Splunk.
    """
    logger.info("Starting Splunk OS enrichment for %d rows...", len(merged_df))

    rows = merged_df.to_dict('records')

    for row in rows:
        ts_str, source    = _resolve_anchor(row)
        row['_ts_str']    = ts_str
        row['_ts_source'] = source
        row['_anchor_dt'] = _splunk_parse_iso(ts_str)

    active_emails = list(dict.fromkeys(
        str(row.get('Email Address') or '').strip().lower()
        for row in rows
        if str(row.get('Email Address') or '').strip()
        and row['_ts_source'] != 'no_action'
        # Skip still-unresolved obfuscated placeholders — they have no real
        # identity in Splunk so querying them wastes time and returns nothing.
        and not str(row.get('Email Address') or '').strip().lower().endswith('@obfuscated.invalid')
    ))
    skipped = len(rows) - len(active_emails)
    logger.info(
        "%d users will be queried in Splunk (failed/reported only) | "
        "%d skipped (no-action / email-opened-only / unresolved obfuscated).",
        len(active_emails), skipped,
    )

    # Early exit — nothing to query
    if not active_emails:
        logger.info("No users need Splunk enrichment. Skipping all phases.")
        for col in ('splunk_lookup_timestamp', 'splunk_ts_source',
                    'splunk_os', 'splunk_os_version', 'splunk_ip', 'splunk_ts'):
            merged_df[col] = ''
        return merged_df

    # ── Phase 1: Proofpoint Splunk ────────────────────────────────────
    logger.info("Phase 1 — Proofpoint Splunk for %d users...", len(active_emails))
    pf_specs = []
    for i in range(0, len(active_emails), SPLUNK_BATCH_SIZE):
        batch = active_emails[i:i + SPLUNK_BATCH_SIZE]
        q, e, l = _proofpoint_splunk_query(batch)
        pf_specs.append((q, e, l, f"Proofpoint-{i}"))
    pf_raw     = _run_batches(pf_specs)
    proofpoint = _parse_proofpoint_splunk(pf_raw)
    logger.info("Phase 1 resolved %d users.", len(proofpoint))

    # ── Phase 2: AzureAD batch ────────────────────────────────────────
    missing = [e for e in active_emails if e not in proofpoint]
    logger.info("Phase 2 — AzureAD batch for %d users...", len(missing))

    email_windows = {}
    date_buckets  = defaultdict(list)
    for row in rows:
        email = str(row.get('Email Address') or '').strip().lower()
        if email not in missing:
            continue
        anchor = row['_anchor_dt']
        if anchor:
            e      = _splunk_time(anchor - timedelta(minutes=TIME_WINDOW_MINUTES))
            l      = _splunk_time(anchor + timedelta(minutes=TIME_WINDOW_MINUTES))
            bucket = anchor.strftime('%Y-%m-%d')
        else:
            e, l   = SPLUNK_CAMPAIGN_EARLIEST, SPLUNK_CAMPAIGN_LATEST
            bucket = 'no_anchor'
        email_windows[email] = (e, l)
        date_buckets[bucket].append(email)

    for k in date_buckets:
        date_buckets[k] = list(dict.fromkeys(date_buckets[k]))

    az_specs = []
    for bucket, bemails in date_buckets.items():
        windows  = [email_windows[em] for em in bemails]
        earliest = min(w[0] for w in windows)
        latest   = max(w[1] for w in windows)
        for i in range(0, len(bemails), SPLUNK_BATCH_SIZE):
            batch = bemails[i:i + SPLUNK_BATCH_SIZE]
            q, e, l = _azuread_query(batch, earliest, latest)
            az_specs.append((q, e, l, f"AzureAD-{bucket}-{i}"))

    az_raw  = _run_batches(az_specs)
    azuread = _parse_azuread(az_raw)
    logger.info("Phase 2 resolved %d users.", len(azuread))

    # ── Phase 3: single-email retry ───────────────────────────────────
    still_missing = [e for e in active_emails if e not in proofpoint and e not in azuread]
    retry_results = _retry_single(still_missing)
    logger.info("Phase 3 resolved %d users.", len(retry_results))

    # ── Assemble output columns ───────────────────────────────────────
    for col in ('splunk_lookup_timestamp', 'splunk_ts_source',
                'splunk_os', 'splunk_os_version', 'splunk_ip', 'splunk_ts'):
        merged_df[col] = ''

    for i, row in enumerate(rows):
        email     = str(row.get('Email Address') or '').strip().lower()
        src       = row['_ts_source']
        anchor_dt = row['_anchor_dt']
        info      = {
            'splunk_os': '', 'splunk_os_version': '',
            'splunk_ip': '', 'splunk_ts': '', 'splunk_ts_source': '',
        }

        if src != 'no_action' and not email.endswith('@obfuscated.invalid'):
            pf_match = _closest_match(proofpoint.get(email, []), anchor_dt)
            if pf_match:
                info = {
                    'splunk_os':         pf_match['os'],
                    'splunk_os_version': pf_match['os_version'],
                    'splunk_ip':         pf_match['ip'],
                    'splunk_ts':         pf_match['ts'],
                    'splunk_ts_source':  f"proofpoint({pf_match['eventtype']})",
                }
            elif azuread.get(email):
                az_match = _closest_match(azuread[email], anchor_dt)
                if az_match:
                    info = {
                        'splunk_os':         az_match['os'],
                        'splunk_os_version': az_match['os_version'],
                        'splunk_ip':         az_match['ip'],
                        'splunk_ts':         az_match['ts'],
                        'splunk_ts_source':  src + '→azuread',
                    }
            elif email in retry_results:
                r = retry_results[email]
                info = {
                    'splunk_os':         r['os'],
                    'splunk_os_version': r['os_version'],
                    'splunk_ip':         r['ip'],
                    'splunk_ts':         r['ts'],
                    'splunk_ts_source':  r['ts_source'],
                }

        merged_df.at[i, 'splunk_lookup_timestamp'] = row['_ts_str']
        merged_df.at[i, 'splunk_ts_source']        = info['splunk_ts_source']
        merged_df.at[i, 'splunk_os']               = info['splunk_os']
        merged_df.at[i, 'splunk_os_version']       = info['splunk_os_version']
        merged_df.at[i, 'splunk_ip']               = info['splunk_ip']
        merged_df.at[i, 'splunk_ts']               = info['splunk_ts']

    resolved  = int((merged_df['splunk_os'] != '').sum())
    no_action = int((merged_df['splunk_ts_source'] == '').sum())
    logger.info("Splunk enrichment complete. Resolved=%d No-action=%d Unresolved=%d",
                resolved, no_action, len(merged_df) - resolved - no_action)
    return merged_df

# ============================================
# MERGE AND EXPORT
# ============================================

def merge_datasets(proofpoint_df, workday_df):
    """
    Left-join Proofpoint records to Workday on email address.
    Workday columns included: all WORKDAY_FIELDS (including FirstName, LastName,
    PayGradeLevelCode, PayGradeLevelDescription) plus Executive Leadership.
    The 'Email Resolved From Obfuscated' column is carried through if present.
    """
    logger.info("Merging Proofpoint and Workday datasets...")

    # Carry through the obfuscated-resolution flag if it was added
    pp_cols = PROOFPOINT_FIELDS + (
        ['Email Resolved From Obfuscated']
        if 'Email Resolved From Obfuscated' in proofpoint_df.columns
        else []
    )

    proofpoint_df_filtered = proofpoint_df[pp_cols].copy()
    workday_df             = add_executive_leadership_column(workday_df)
    workday_df_filtered    = workday_df[WORKDAY_FIELDS + ['Executive Leadership']].copy()

    proofpoint_df_filtered['Email Address']     = proofpoint_df_filtered['Email Address'].str.lower().str.strip()
    workday_df_filtered['InternetEmailAddress'] = workday_df_filtered['InternetEmailAddress'].str.lower().str.strip()

    merged_df = pd.merge(
        proofpoint_df_filtered, workday_df_filtered,
        left_on='Email Address', right_on='InternetEmailAddress',
        how='left', suffixes=('_Proofpoint', '_Workday'),
    )
    if 'InternetEmailAddress' in merged_df.columns:
        merged_df = merged_df.drop(columns=['InternetEmailAddress'])

    logger.info("Merged: %d records. Matched=%d Unmatched=%d",
                len(merged_df),
                int(merged_df['GlobalId'].notna().sum()),
                int(merged_df['GlobalId'].isna().sum()))
    return merged_df


def export_to_excel_with_sheets(workday_df, proofpoint_df, merged_df, output_path):
    """
    3-sheet workbook.
    Workday Feed sheet includes PayGradeLevelCode, PayGradeLevelDescription,
    FirstName, LastName. Merged Data sheet includes Splunk OS enrichment
    columns, Tenure, and Email Resolved From Obfuscated.
    """
    logger.info("Exporting to Excel (3 sheets)...")
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            workday_df.to_excel(writer,    sheet_name='Workday Feed',    index=False)
            proofpoint_df.to_excel(writer, sheet_name='Proofpoint Data', index=False)
            merged_df.to_excel(writer,     sheet_name='Merged Data',     index=False)
            for sheet_name in writer.sheets:
                ws = writer.sheets[sheet_name]
                for column in ws.columns:
                    max_length = max(
                        (len(str(cell.value or '')) for cell in column), default=10
                    )
                    ws.column_dimensions[column[0].column_letter].width = min(max_length + 2, 50)
                ws.freeze_panes = 'A2'
        logger.info("Excel saved: %s", output_path)
    except Exception as e:
        logger.exception("Failed to write Excel: %s", e)
        csv_path = output_path.replace('.xlsx', '_merged.csv')
        merged_df.to_csv(csv_path, index=False, encoding='utf-8')
        logger.info("Fallback CSV saved: %s", csv_path)


def export_merged_to_csv(merged_df, output_csv_path):
    """Flat CSV of Merged Data (with Splunk columns and Tenure)."""
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
        # Step 1: Workday (fetches FirstName, LastName, PayGrade fields, etc.)
        workday_records = fetch_workday_workers()
        workday_df      = pd.DataFrame(workday_records)
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

        # Step 3: Transform
        proofpoint_df = pd.DataFrame(transform_proofpoint_data(proofpoint_records))

        # Step 4: Resolve obfuscated emails via Workday FirstName / LastName match.
        # Rows where a unique name match is found have their placeholder email
        # replaced with the real Workday InternetEmailAddress before the merge,
        # so all downstream steps (merge, tenure, Splunk) work on the real email.
        proofpoint_df = resolve_obfuscated_emails(proofpoint_df, workday_df)

        # Step 5: Merge Proofpoint → Workday on email address
        merged_df = merge_datasets(proofpoint_df, workday_df)

        # Step 6: Compute Tenure
        # Reference date = CAMPAIGN_START_DATE env var.
        # Anchor = ReHireDate if set, else HireDate. Result in decimal years.
        merged_df = compute_tenure(merged_df, WORKDAY_CONFIG['campaign_start_date'])

        # Step 7: Splunk OS enrichment
        merged_df = enrich_with_splunk_os(merged_df)

        # Step 8: Export Excel
        export_to_excel_with_sheets(workday_df, proofpoint_df, merged_df,
                                    OUTPUT_CONFIG['output_excel'])

        # Step 9: Export merged CSV
        export_merged_to_csv(merged_df, OUTPUT_CONFIG['output_csv'])

        # ── Summary ───────────────────────────────────────────────────
        tenure_res = int(merged_df['Tenure'].notna().sum()) \
                     if 'Tenure' in merged_df.columns else 0
        splunk_res = int((merged_df.get('splunk_os', pd.Series(dtype=str)) != '').sum()) \
                     if 'splunk_os' in merged_df.columns else 0
        obfusc_res = int(
            (proofpoint_df.get('Email Resolved From Obfuscated', pd.Series(dtype=str)) == 'TRUE').sum()
        ) if 'Email Resolved From Obfuscated' in proofpoint_df.columns else 0

        logger.info("=" * 70)
        logger.info("EXPORT COMPLETE")
        logger.info("Rows                    : %d", len(merged_df))
        logger.info("Obfuscated resolved     : %d", obfusc_res)
        logger.info("Tenure resolved         : %d", tenure_res)
        logger.info("Splunk resolved         : %d", splunk_res)
        logger.info("Excel: %s", OUTPUT_CONFIG['output_excel'])
        logger.info("CSV:   %s", OUTPUT_CONFIG['output_csv'])
        logger.info("=" * 70)

    except KeyboardInterrupt:
        logger.warning("Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.exception("Unhandled exception: %s", e)
        sys.exit(1)


if __name__ == '__main__':
    main()