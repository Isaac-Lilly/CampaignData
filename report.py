import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
import sys
import time
import os
from dotenv import load_dotenv

load_dotenv()

# ============================================
# CONFIGURATION
# ============================================

# Workday API Configuration with Date Range
WORKDAY_CONFIG = {
    'client_id': os.getenv('WORKDAY_CLIENT_ID'),
    'client_secret': os.getenv('WORKDAY_CLIENT_SECRET'),
    'token_url': os.getenv('WORKDAY_TOKEN_URL'),
    'api_url': os.getenv('WORKDAY_API_URL'),
    'scope': os.getenv('WORKDAY_SCOPE'),
    'campaign_start_date': os.getenv('CAMPAIGN_START_DATE', '2026-02-08'),
}

# Proofpoint API Configuration - UPDATED WITH BETTER RATE LIMITING
PROOFPOINT_CONFIG = {
    'base_url': os.getenv('PROOFPOINT_BASE_URL'),
    'api_key': os.getenv('PROOFPOINT_API_KEY'),
    'start_date': os.getenv('PROOFPOINT_START_DATE', '2026-02-08'),
    'end_date': os.getenv('PROOFPOINT_END_DATE', '2026-02-15'),
    'page_size': int(os.getenv('PROOFPOINT_PAGE_SIZE', '500')),
    'verify_ssl': os.getenv('PROOFPOINT_VERIFY_SSL', 'False').lower() == 'true',
    'rate_limit_delay': float(os.getenv('PROOFPOINT_RATE_LIMIT_DELAY', '1.0')),
    'retry_delay': float(os.getenv('PROOFPOINT_RETRY_DELAY', '5.0')),
    'max_retries': int(os.getenv('PROOFPOINT_MAX_RETRIES', '3'))
}

# Output Configuration
OUTPUT_CONFIG = {
    'output_excel': os.getenv('OUTPUT_EXCEL_PATH', r'C:\WorkdaySADFeed\Merged_Campaign_Details.xlsx'),
    'output_csv': os.getenv('OUTPUT_CSV_PATH', r'C:\WorkdaySADFeed\Merged_Campaign_Details.csv')
}

# Field mappings for selective data extraction
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
    'False Positive'
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
    'JobSubFunctionDescription'
]


# ============================================
# ✅ HELPER FUNCTIONS FOR FALSE POSITIVE DETECTION
# ============================================

def parse_timestamp(timestamp_str):
    """Parse ISO 8601 timestamp to datetime object"""
    if not timestamp_str or pd.isna(timestamp_str):
        return None
    
    try:
        if isinstance(timestamp_str, str):
            timestamp_str = timestamp_str.replace('Z', '+00:00')
            return pd.to_datetime(timestamp_str)
        return pd.to_datetime(timestamp_str)
    except Exception as e:
        print(f"    ⚠️  Error parsing timestamp '{timestamp_str}': {e}")
        return None


def is_false_positive(date_sent, date_clicked, whois_isp):
    """
    Determine if a click is a false positive based on:
    1. Whois ISP contains 'Microsoft Azure'
    2. Time between sent and clicked <= 60 seconds

    Returns: True if false positive, False otherwise
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
        print(f"    🔍 False Positive Detected:")
        print(f"       Date Sent: {date_sent}, Date Clicked: {date_clicked}")
        print(f"       Time Diff: {time_diff:.2f}s, ISP: {whois_isp}")
    
    return is_fp


def add_executive_leadership_column(df):
    """
    Add 'Executive Leadership' column based on JobSubFunctionCode.
    True if JobSubFunctionCode == 'JFA000011', False otherwise.
    """
    if 'JobSubFunctionCode' in df.columns:
        df['Executive Leadership'] = df['JobSubFunctionCode'].apply(
            lambda x: True if pd.notna(x) and str(x).strip() == 'JFA000011' else False
        )
        exec_count = df['Executive Leadership'].sum()
        print(f"  ✅ Executive Leadership column added")
        print(f"     👔 Executives identified: {exec_count}")
    else:
        df['Executive Leadership'] = False
        print("  ⚠️  'JobSubFunctionCode' column not found. All marked as False.")
    
    return df


# ============================================
# WORKDAY API FUNCTIONS
# ============================================

def get_workday_access_token():
    """Get access token for Workday API"""
    print("Getting Workday access token...")
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': WORKDAY_CONFIG['client_id'],
        'client_secret': WORKDAY_CONFIG['client_secret'],
        'scope': WORKDAY_CONFIG['scope']
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    try:
        response = requests.post(WORKDAY_CONFIG['token_url'], data=data, headers=headers)
        response.raise_for_status()
        token_info = response.json()
        print("  ✅ Token acquired")
        return token_info['access_token']
    except Exception as e:
        print(f"  ❌ Error getting token: {e}")
        raise


def fetch_workday_workers():
    """Fetch workers from Workday API - Active OR Terminated on/after campaign start"""
    print("\n📊 Fetching Workday worker data...")
    print(f"  📅 Date filter: Active OR TerminationDate >= {WORKDAY_CONFIG['campaign_start_date']} (campaign start)")
    
    access_token = get_workday_access_token()
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
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
        
        paginated_url = f"{WORKDAY_CONFIG['api_url']}?{filter_query}&$select={select_fields}&$top={page_size}&$skip={skip}"
        
        try:
            response = requests.get(paginated_url, headers=headers, timeout=60)
            response.raise_for_status()
            data = response.json()
            records = data.get('value', [])
            
            if not records:
                break
            
            all_records.extend(records)
            print(f"  ✅ Fetched {len(records)} records... Total: {len(all_records)}")
            skip += page_size
            
        except requests.exceptions.RequestException as e:
            print(f"  ❌ Error: {e}")
            if hasattr(e, 'response') and hasattr(e.response, 'text'):
                print(f"  📄 Response details: {e.response.text[:500]}")
            break

    print(f"  ✅ Total Workday records: {len(all_records)}\n")
    return all_records


# ============================================
# PROOFPOINT API FUNCTIONS
# ============================================

def fetch_proofpoint_records():
    """Fetch all records from Proofpoint API with improved rate limit handling.
    
    Includes filter[_includedeletedusers]=TRUE to ensure parity between
    API and UI user counts by returning all users including deleted ones.
    """
    print("📧 Fetching Proofpoint phishing data...")
    print("  ℹ️  Including deleted users for full dataset parity with UI")
    
    all_records = []
    page_number = 1
    has_more_pages = True
    
    headers = {
        'x-apikey-token': PROOFPOINT_CONFIG['api_key']
    }
    
    while has_more_pages:
        print(f"  Fetching page {page_number}...")
        
        params = {
            'page[number]': page_number,
            'page[size]': PROOFPOINT_CONFIG['page_size'],
            'filter[_eventtimestamp_start]': PROOFPOINT_CONFIG['start_date'],
            'filter[_eventtimestamp_end]': PROOFPOINT_CONFIG['end_date'],
            'filter[_includedeletedusers]': 'TRUE',   # ✅ Include deleted users
        }
        
        params = {k: v for k, v in params.items() if v is not None}
        
        retry_count = 0
        success = False
        
        while retry_count < PROOFPOINT_CONFIG['max_retries'] and not success:
            try:
                if page_number > 1 or retry_count > 0:
                    delay = PROOFPOINT_CONFIG['rate_limit_delay']
                    print(f"    ⏱️  Rate limit: waiting {delay}s...")
                    time.sleep(delay)
                
                response = requests.get(
                    PROOFPOINT_CONFIG['base_url'],
                    headers=headers,
                    params=params,
                    timeout=30,
                    verify=PROOFPOINT_CONFIG['verify_ssl']
                )
                
                # Handle 429 Too Many Requests
                if response.status_code == 429:
                    retry_count += 1
                    retry_after = int(response.headers.get('Retry-After', PROOFPOINT_CONFIG['retry_delay']))
                    print(f"    ⚠️  429 Too Many Requests - Retry {retry_count}/{PROOFPOINT_CONFIG['max_retries']}")
                    print(f"    Waiting {retry_after}s before retry...")
                    time.sleep(retry_after)
                    continue

                # Handle 504 Gateway Timeout
                if response.status_code == 504:
                    retry_count += 1
                    wait_time = PROOFPOINT_CONFIG['retry_delay'] * retry_count  # Backoff: 5s, 10s, 15s
                    print(f"    ⚠️  504 Gateway Timeout - Retry {retry_count}/{PROOFPOINT_CONFIG['max_retries']}")
                    print(f"    Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                    continue
                
                response.raise_for_status()
                
                data = response.json()
                
                if data.get('data') and len(data['data']) > 0:
                    all_records.extend(data['data'])
                    print(f"    ✅ Retrieved {len(data['data'])} records (Total: {len(all_records)})")
                    page_number += 1
                    success = True
                else:
                    has_more_pages = False
                    success = True
                    
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    retry_count += 1
                    retry_after = int(e.response.headers.get('Retry-After', PROOFPOINT_CONFIG['retry_delay']))
                    print(f"    ⚠️  HTTP 429 - Retry {retry_count}/{PROOFPOINT_CONFIG['max_retries']}")
                    print(f"    Waiting {retry_after}s...")
                    time.sleep(retry_after)
                elif e.response.status_code == 504:
                    retry_count += 1
                    wait_time = PROOFPOINT_CONFIG['retry_delay'] * retry_count  # Backoff: 5s, 10s, 15s
                    print(f"    ⚠️  HTTP 504 Gateway Timeout - Retry {retry_count}/{PROOFPOINT_CONFIG['max_retries']}")
                    print(f"    Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    print(f"    ❌ HTTP Error: {e}")
                    has_more_pages = False
                    success = True
                    
            except requests.exceptions.RequestException as e:
                print(f"    ❌ Request Error: {e}")
                if retry_count < PROOFPOINT_CONFIG['max_retries'] - 1:
                    retry_count += 1
                    wait_time = PROOFPOINT_CONFIG['retry_delay']
                    print(f"    Retrying in {wait_time}s... ({retry_count}/{PROOFPOINT_CONFIG['max_retries']})")
                    time.sleep(wait_time)
                else:
                    has_more_pages = False
                    success = True
        
        if retry_count >= PROOFPOINT_CONFIG['max_retries']:
            print(f"    ⚠️  Max retries reached for page {page_number}. Stopping.")
            has_more_pages = False
            
    print(f"\n  ✅ Total Proofpoint records fetched: {len(all_records)}\n")
    return all_records


def transform_proofpoint_data(records):
    """Transform Proofpoint API data with FALSE POSITIVE DETECTION"""
    print("🔄 Transforming Proofpoint data with false positive detection...")
    
    grouped = defaultdict(list)
    for record in records:
        attrs = record['attributes']
        key = f"{attrs['user_guid']}_{attrs['campaign_guid']}"
        grouped[key].append(record)
    
    transformed_data = []
    false_positive_count = 0
    
    for key, events in grouped.items():
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
        
        # Prioritize events with Whois data
        whois_source = None
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
        
        record = {
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
        
        transformed_data.append(record)
    
    print(f"  ✅ Transformed {len(transformed_data)} unique records")
    print(f"  🔍 False Positives Detected: {false_positive_count}\n")
    return transformed_data


# ============================================
# MERGE AND EXPORT FUNCTIONS
# ============================================

def merge_datasets(proofpoint_df, workday_df):
    """Merge Proofpoint and Workday data on email address - INCLUDES Executive Leadership"""
    print("🔗 Merging Proofpoint and Workday data...")
    
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
        suffixes=('_Proofpoint', '_Workday')
    )
    
    if 'InternetEmailAddress' in merged_df.columns:
        merged_df = merged_df.drop(columns=['InternetEmailAddress'])
    
    print(f"  ✅ Merged records: {len(merged_df)}")
    print(f"  ✅ Matched with Workday: {merged_df['GlobalId'].notna().sum()}")
    print(f"  ⚠️  Not matched: {merged_df['GlobalId'].isna().sum()}")
    
    fp_count = (merged_df['False Positive'] == 'TRUE').sum()
    print(f"  🔍 False Positives in Merged Data: {fp_count}")
    
    exec_count = merged_df['Executive Leadership'].sum()
    print(f"  👔 Executives in Merged Data: {exec_count}\n")
    
    return merged_df


def export_to_excel_with_sheets(workday_df, proofpoint_df, merged_df, output_path):
    """Export data to Excel with THREE separate sheets"""
    print(f"💾 Exporting to Excel with 3 sheets...")
    
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
            workday_df.to_excel(writer, sheet_name='Workday Feed', index=False)
            print(f"  ✅ Sheet 1: Workday Feed ({len(workday_df)} rows)")
            
            proofpoint_df.to_excel(writer, sheet_name='Proofpoint Data', index=False)
            print(f"  ✅ Sheet 2: Proofpoint Data ({len(proofpoint_df)} rows)")
            
            merged_df.to_excel(writer, sheet_name='Merged Data', index=False)
            print(f"  ✅ Sheet 3: Merged Data ({len(merged_df)} rows)")
            
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                
                for column in worksheet.columns:
                    max_length = 0
                    column_letter = column[0].column_letter
                    for cell in column:
                        try:
                            if len(str(cell.value)) > max_length:
                                max_length = len(str(cell.value))
                        except:
                            pass
                    adjusted_width = min(max_length + 2, 50)
                    worksheet.column_dimensions[column_letter].width = adjusted_width
                
                worksheet.freeze_panes = 'A2'
        
        print(f"\n  ✅ Excel saved: {output_path}\n")
        
    except Exception as e:
        print(f"  ❌ Error saving Excel: {e}")
        csv_path = output_path.replace('.xlsx', '_merged.csv')
        merged_df.to_csv(csv_path, index=False, encoding='utf-8')
        print(f"  ✅ CSV saved instead: {csv_path}\n")


# ============================================
# MAIN FUNCTION
# ============================================

def main():
    """Main execution function"""
    print("="*70)
    print("  MERGED PROOFPOINT + WORKDAY CAMPAIGN DETAILS EXPORT")
    print("  ✅ WITH FALSE POSITIVE DETECTION")
    print("  ✅ WITH EXECUTIVE LEADERSHIP IDENTIFICATION")
    print("  ✅ WITH DELETED USERS INCLUDED (API/UI PARITY)")
    print("="*70)
    print()
    print(f"📅 Proofpoint Campaign: {PROOFPOINT_CONFIG['start_date']} to {PROOFPOINT_CONFIG['end_date']}")
    print(f"📅 Workday Filter: Active OR TerminationDate >= {WORKDAY_CONFIG['campaign_start_date']}")
    print(f"📄 Page Size: {PROOFPOINT_CONFIG['page_size']}")
    print(f"⏱️  Rate Limit Delay: {PROOFPOINT_CONFIG['rate_limit_delay']}s between requests")
    print(f"🔄 Retry Delay: {PROOFPOINT_CONFIG['retry_delay']}s after 429 errors")
    print(f"🔁 Max Retries: {PROOFPOINT_CONFIG['max_retries']}")
    print(f"🔍 False Positive Detection: Microsoft Azure + ≤60s click")
    print(f"👔 Executive Leadership: JobSubFunctionCode == 'JFA000011'")
    print(f"🗑️  Deleted Users: Included (filter[_includedeletedusers]=TRUE)")
    print(f"📊 Proofpoint Fields: {len(PROOFPOINT_FIELDS)}")
    print(f"📊 Workday Fields: {len(WORKDAY_FIELDS)} (+ Executive Leadership)")
    
    if not PROOFPOINT_CONFIG['verify_ssl']:
        print("⚠️  SSL verification is disabled")
    
    print()
    
    try:
        # Step 1: Fetch Workday data
        workday_records = fetch_workday_workers()
        workday_df = pd.DataFrame(workday_records)
        
        if workday_df.empty:
            print("⚠️  No Workday records found")
            workday_df = pd.DataFrame(columns=WORKDAY_FIELDS + ['Executive Leadership'])
        else:
            workday_df = workday_df[workday_df['InternetEmailAddress'].notna()]
            workday_df = workday_df[workday_df['InternetEmailAddress'].str.strip() != '']
            
            workday_df = add_executive_leadership_column(workday_df)
            
            active_count = len(workday_df[workday_df['StatusDescription'] == 'Active'])
            terminated_count = len(workday_df[workday_df['StatusDescription'] != 'Active'])
            exec_count = workday_df['Executive Leadership'].sum()
            
            print(f"\n✅ Total Workday records: {len(workday_df)}")
            print(f"   - Active: {active_count}")
            print(f"   - Terminated (on/after {WORKDAY_CONFIG['campaign_start_date']}): {terminated_count}")
            print(f"   👔 Executives: {exec_count}\n")
        
        # Step 2: Fetch Proofpoint data (includes deleted users)
        proofpoint_records = fetch_proofpoint_records()
        
        if not proofpoint_records:
            print("❌ No Proofpoint records found. Exiting.")
            sys.exit(1)
        
        # Step 3: Transform Proofpoint data
        proofpoint_transformed = transform_proofpoint_data(proofpoint_records)
        proofpoint_df = pd.DataFrame(proofpoint_transformed)
        
        # Step 4: Merge datasets
        merged_df = merge_datasets(proofpoint_df, workday_df)
        
        # Step 5: Export to Excel with 3 sheets
        export_to_excel_with_sheets(workday_df, proofpoint_df, merged_df, OUTPUT_CONFIG['output_excel'])
        
        # Final Summary
        fp_count = (proofpoint_df['False Positive'] == 'TRUE').sum()
        exec_count_workday = workday_df['Executive Leadership'].sum()
        exec_count_merged = merged_df['Executive Leadership'].sum()
        
        print()
        print("="*70)
        print("✅ EXPORT COMPLETE")
        print("="*70)
        print(f"📊 Sheet 1 - Workday Feed: {len(workday_df)} records")
        print(f"   👔 Executives: {exec_count_workday}")
        print(f"📊 Sheet 2 - Proofpoint Data: {len(proofpoint_df)} records")
        print(f"   🔍 False Positives: {fp_count}")
        print(f"   🗑️  Includes deleted users: YES")
        print(f"📊 Sheet 3 - Merged Data: {len(merged_df)} records")
        print(f"   - Matched with Workday: {merged_df['GlobalId'].notna().sum()}")
        print(f"   - Not matched: {merged_df['GlobalId'].isna().sum()}")
        print(f"   👔 Executives: {exec_count_merged}")
        print(f"   🔍 False Positives: {(merged_df['False Positive'] == 'TRUE').sum()}")
        print(f"💾 Output: {OUTPUT_CONFIG['output_excel']}")
        print()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()