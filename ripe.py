# -----------------------------------------------------------------------------
# Author: Sebastian Michel
# Company: Rootsektor IT-Security GmbH
# License: MIT License
# Version: 0.1
#
# This tool is developed to interact with the RIPE Database API, enabling
# detailed queries, filtering, CIDR conversion, and output customization.
# Released under the MIT License, this software is free to use and modify
# with proper attribution.
#
# License Text:
# MIT License
#
# Copyright (c) {2024} Rootsektor IT-Security GmbH
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# -----------------------------------------------------------------------------

import requests
import xml.etree.ElementTree as ET
import argparse
from netaddr import IPRange, cidr_merge
import urllib.parse
import json
import sys
import re

VERSION = "0.1"

def about():
    print(f"""Ripe API Query Tool - v{VERSION}""")

def query_ripe_api(base_url, query, start=0, rows=10):
    """
    Query the RIPE API with the specified query parameters.
    :param base_url: Base URL for the RIPE API.
    :param query: Query string.
    :param start: Starting index for the results.
    :param rows: Number of results to fetch per page.
    :return: Parsed XML or JSON response.
    """
    # Automatically escape the query
    escaped_query = urllib.parse.quote_plus(query)
    url = f"{base_url}?facet=true&format=xml&hl=true&q={escaped_query}&start={start}&rows={rows}&wt=json"
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        content_type = response.headers.get('Content-Type', '')
        
        if 'application/json' in content_type:
            return response.json()
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            return ET.fromstring(response.text)  # Parse XML
        else:
            print(f"Unexpected content type: {content_type}")
            print(f"Response text: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
        return None

def extract_fields_from_xml(xml_response, filters):
    """
    Extract specified fields from the XML API response.
    :param xml_response: Parsed XML response.
    :param filters: List of fields to extract. If None, extract all fields.
    :return: List of dictionaries containing the extracted fields.
    """
    extracted_data = []
    for doc in xml_response.findall(".//doc"):
        entry = {}
        for field in doc.findall(".//str"):
            field_name = field.attrib.get("name")
            if field_name:
                if field_name.lower() == "inetnum":
                    # Map 'inetnum' to 'inetnum' to maintain consistency
                    entry["inetnum"] = field.text.strip()
                elif not filters or field_name.lower() in filters:
                    entry[field_name.lower()] = field.text.strip()
        if filters:
            # Ensure all filter fields are present; set to empty string if missing
            for f in filters:
                if f not in entry:
                    entry[f] = ""
        extracted_data.append(entry)
    return extracted_data

def extract_fields_from_json(json_response, filters):
    """
    Extract specified fields from the JSON API response.
    :param json_response: Parsed JSON response.
    :param filters: List of fields to extract. If None, extract all fields.
    :return: List of dictionaries containing the extracted fields.
    """
    extracted_data = []
    docs = json_response.get('result', {}).get('docs', [])
    for doc in docs:
        entry = {}
        for field in doc.get("strs", []):
            field_name = field.get("name")
            field_value = field.get("value")
            if field_name and field_value:
                if field_name.lower() == "inetnum":
                    # Map 'inetnum' to 'inetnum' to maintain consistency
                    entry["inetnum"] = field_value.strip()
                elif not filters or field_name.lower() in filters:
                    entry[field_name.lower()] = field_value.strip()
        if filters:
            # Ensure all filter fields are present; set to empty string if missing
            for f in filters:
                if f not in entry:
                    entry[f] = ""
        extracted_data.append(entry)
    return extracted_data

def convert_to_cidr(inetnum):
    """
    Convert an IP range to CIDR blocks.
    :param inetnum: IP range in "start - end" format.
    :return: List of CIDR blocks.
    """
    try:
        # Remove any trailing hyphens and spaces
        inetnum_clean = re.sub(r'\s*-\s*$', '', inetnum)
        start_ip, end_ip = inetnum_clean.split(' - ')
        ip_range_obj = IPRange(start_ip.strip(), end_ip.strip())
        cidr_blocks = cidr_merge(ip_range_obj)  # Merge into smallest CIDR blocks
        return [str(block) for block in cidr_blocks]
    except Exception as e:
        print(f"Error converting inetnum '{inetnum}' to CIDR: {e}")
        return [inetnum]  # Fallback to original range

def prepare_targets(extracted_entries, filters, cidr_flag, unique_flag):
    """
    Prepares the target data based on filters, CIDR conversion, and deduplication.
    :param extracted_entries: List of dictionaries containing the extracted fields.
    :param filters: List of fields to include in the output.
    :param cidr_flag: Boolean indicating if CIDR conversion is requested.
    :param unique_flag: Boolean indicating if duplicates should be removed.
    :return: Tuple containing headers and list of row lists.
    """
    targets = []
    seen = set()  # For deduplication

    if filters:
        headers = filters.copy()
        for entry in extracted_entries:
            # Check if all filter fields are empty; skip if so
            if all(not entry.get(field, "") for field in filters):
                continue
            row = []
            for field in filters:
                value = entry.get(field, "")
                if field == "inetnum" and cidr_flag and value:
                    cidrs = convert_to_cidr(value)
                    value = ','.join(cidrs)
                row.append(value)
            # Skip rows with all empty values
            if any(row):
                row_tuple = tuple(row)
                if unique_flag:
                    if row_tuple in seen:
                        continue
                    seen.add(row_tuple)
                targets.append(row)
    else:
        # No filters; extract all fields
        headers = sorted({key for entry in extracted_entries for key in entry.keys()})
        for entry in extracted_entries:
            row = []
            for field in headers:
                value = entry.get(field, "")
                if field == "inetnum" and cidr_flag and value:
                    cidrs = convert_to_cidr(value)
                    value = ','.join(cidrs)
                row.append(value)
            if any(row):
                row_tuple = tuple(row)
                if unique_flag:
                    if row_tuple in seen:
                        continue
                    seen.add(row_tuple)
                targets.append(row)
    return headers, targets

def print_table(headers, rows):
    """
    Prints a table with headers and rows.
    :param headers: List of header strings.
    :param rows: List of row lists.
    """
    if not headers:
        print("No data to display.")
        return

    # Calculate the maximum width for each column
    column_widths = [len(header) for header in headers]
    for row in rows:
        for i, cell in enumerate(row):
            column_widths[i] = max(column_widths[i], len(str(cell)))

    # Create format string
    row_format = ' | '.join(['{{:<{}}}'.format(w) for w in column_widths])

    # Print header
    print(row_format.format(*headers))
    # Print separator
    print('-+-'.join(['-' * w for w in column_widths]))
    # Print rows
    for row in rows:
        print(row_format.format(*row))

def print_grepable(headers, rows, separator):
    """
    Prints the results in a grepable format with specified separator.
    :param headers: List of header strings.
    :param rows: List of row lists.
    :param separator: Separator string for fields.
    """
    if not headers:
        print("No data to display.")
        return

    # Print headers
    print(separator.join(headers))
    # Print rows
    for row in rows:
        print(separator.join(row))

def print_list(headers, rows, use_separators, separator):
    if use_separators:
        # Traditional list format with 'Parameter: value' and separators
        separator_line = '-' * 30
        for row in rows:
            print(separator_line)
            for header, value in zip(headers, row):
                if value:  # Only print if value is not empty
                    print(f"{header}: {value}")
        if rows:
            print(separator_line)
    else:
        # Plain output with values separated by the specified separator
        for row in rows:
            # Retain all fields, including empty ones
            print(separator.join(row))


def output_results(headers, rows, output_type, output_file, table_flag, grepable_flag, separator, list_flag, filter_set):
    """
    Outputs the results in the specified format.
    :param headers: List of header strings.
    :param rows: List of row lists.
    :param output_type: Type of output ('plain', 'json', 'xml').
    :param output_file: File path to write the output.
    :param table_flag: Boolean indicating if table format is requested.
    :param grepable_flag: Boolean indicating if grepable format is requested.
    :param separator: Separator string for grepable and plain formats.
    :param list_flag: Boolean indicating if list format is requested.
    :param filter_set: Boolean indicating if a filter was set.
    """
    output_data = ""

    if output_type == "plain":
        if table_flag:
            # Output as table
            if not headers:
                output_data = "No data to display."
            else:
                from io import StringIO
                import sys

                # Capture the table output
                output = StringIO()
                original_stdout = sys.stdout
                sys.stdout = output
                print_table(headers, rows)
                sys.stdout = original_stdout
                output_data = output.getvalue()
        elif grepable_flag:
            # Output in grepable format
            if not headers:
                output_data = "No data to display."
            else:
                from io import StringIO
                import sys

                # Capture the grepable output
                output = StringIO()
                original_stdout = sys.stdout
                sys.stdout = output
                print_grepable(headers, rows, separator)
                sys.stdout = original_stdout
                output_data = output.getvalue()
        elif list_flag:
            # Output in list format
            if not headers:
                output_data = "No data to display."
            else:
                from io import StringIO
                import sys

                # Capture the list output
                output = StringIO()
                original_stdout = sys.stdout
                sys.stdout = output
                print_list(headers, rows, not filter_set, separator)
                sys.stdout = original_stdout
                output_data = output.getvalue()
        else:
            output_data = "No output format selected."
    elif output_type == "json":
        if len(headers) > 1:
            # Convert rows to list of dicts
            data = [dict(zip(headers, row)) for row in rows]
        elif len(headers) == 1:
            # Convert rows to list of values
            data = [row[0] for row in rows]
        else:
            data = []
        output_data = json.dumps(data, indent=2)
    elif output_type == "xml":
        root = ET.Element("Targets")
        for row in rows:
            target_elem = ET.SubElement(root, "Target")
            if len(headers) > 1:
                for header, value in zip(headers, row):
                    field_elem = ET.SubElement(target_elem, header)
                    field_elem.text = value
            elif len(headers) == 1:
                field_elem = ET.SubElement(target_elem, headers[0])
                field_elem.text = row[0]
        output_data = ET.tostring(root, encoding='unicode')
    else:
        print(f"Unsupported output type: {output_type}")
        return

    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(output_data)
            print(f"Output written to {output_file}")
        except Exception as e:
            print(f"Failed to write to file {output_file}: {e}")
    else:
        print(output_data)

def main():
    parser = argparse.ArgumentParser(
        description="RIPE API Subnet Query Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  Basic Usage (List Format - Default):
    python3 ripe.py --query <search string> --filter subnet

  Basic Usage (List Format with CIDR Conversion):
    python3 ripe.py --query <search string> --filter subnet --cidr

  Output as a Table:
    python3 ripe.py --query <search string> --filter subnet,netname --table

  Output as a Table with CIDR Conversion:
    python3 ripe.py --query <search string> --filter subnet,netname --table --cidr

  Output in Grepable Format with Default Separator (Comma):
    python3 ripe.py --query <search string> --filter subnet --grepable

  Output in Grepable Format with Custom Separator (`;`):
    python3 ripe.py --query <search string> --filter subnet --grepable --separator ";"

  Output to File in Plain Text:
    python3 ripe.py --query <search string> --filter netname,inetnum --output targets.txt --output-type plain

  Output to File in JSON:
    python3 ripe.py --query <search string> --filter netname,inetnum --cidr --output targets.json --output-type json

  Output to File in XML:
    python3 ripe.py --query <search string> --filter netname,inetnum --cidr --output targets.xml --output-type xml

  Remove Duplicates from Output:
    python3 ripe.py --query <search string> --filter netname,inetnum --cidr --unique
        """
    )
    parser.add_argument(
        "--query", "-q",
        type=str,
        required=True,
        help="The search string to use for the RIPE API query."
    )
    parser.add_argument(
        "--filter", "-f",
        type=str,
        required=False,
        help=(
            "Comma-separated list of fields to extract and include in the output.\n"
            "Available fields include: inetnum, netname, person, admin-c, descr, country, status, etc."
        )
    )
    parser.add_argument(
        "--separator", "-s",
        type=str,
        default=",",
        help="Separator string for grepable and plain formats (default: ',')."
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        help="Output file path."
    )
    parser.add_argument(
        "--output-type", "-t",
        type=str,
        choices=["plain", "json", "xml"],
        default="plain",
        help="Output format: plain, json, xml (default: plain)."
    )
    parser.add_argument(
        "--table", "-T",
        action='store_true',
        help="Output results as a table."
    )
    parser.add_argument(
        "--grepable", "-g",
        action='store_true',
        help="Output results in a grepable format."
    )
    parser.add_argument(
        "--cidr", "-c",
        action='store_true',
        help="Convert subnet ranges to CIDR notation."
    )
    parser.add_argument(
        "--unique", "-u",
        action='store_true',
        help="Remove duplicate entries from the output."
    )
    args = parser.parse_args()
    
    # Parse the filter fields
    if args.filter:
        filters = [field.strip().lower() for field in args.filter.split(',')]
        # Ensure consistent field naming
        filters = ['inetnum' if f == 'inetnum' else f for f in filters]
        filter_set = True
    else:
        filters = None  # Extract all fields
        filter_set = False
    
    base_url = "https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select"
    query = f'"{args.query}"'
    
    # Initial query to get the total number of results
    initial_response = query_ripe_api(base_url, query, start=0, rows=1)
    if not initial_response:
        print("Failed to retrieve initial response.")
        sys.exit(1)

    if isinstance(initial_response, ET.Element):
        # Handle XML response
        total_results = int(initial_response.find(".//result").attrib.get("numFound", 0))
    elif isinstance(initial_response, dict):
        # Handle JSON response (fallback)
        total_results = initial_response.get('result', {}).get('numFound', 0)
    else:
        print("Unexpected response format.")
        sys.exit(1)

    print(f"Total results found: {total_results}")
    
    all_extracted_entries = []
    rows_per_page = 100  # Number of results per page (adjust as needed)
    
    # Paginate through results
    for start in range(0, total_results, rows_per_page):
        print(f"Fetching results starting from {start}...")
        response = query_ripe_api(base_url, query, start=start, rows=rows_per_page)
        
        if not response:
            print(f"Failed to fetch results for start={start}.")
            continue

        if isinstance(response, ET.Element):
            # Extract fields from XML
            extracted_entries = extract_fields_from_xml(response, filters)
        elif isinstance(response, dict):
            # Extract fields from JSON
            extracted_entries = extract_fields_from_json(response, filters)
        else:
            print("Unexpected response format during pagination.")
            continue
        
        all_extracted_entries.extend(extracted_entries)
    
    if not all_extracted_entries:
        print("No data extracted.")
        sys.exit(0)
    
    # Prepare targets based on filters, CIDR flag, and uniqueness
    headers, targets = prepare_targets(all_extracted_entries, filters, args.cidr, args.unique)
    
    # Determine output mode
    table_flag = args.table
    grepable_flag = args.grepable
    list_flag = not table_flag and not grepable_flag and args.output_type == "plain"
    
    # Output the results
    output_results(headers, targets, args.output_type, args.output, table_flag, grepable_flag, args.separator, list_flag, filter_set)

if __name__ == "__main__":
    about()
    main()
