
# RIPE API Query Tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Command-Line Arguments](#command-line-arguments)
  - [Examples](#examples)
- [Output Formats](#output-formats)
- [Handling Duplicates](#handling-duplicates)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Overview

The **RIPE API Query Tool** is a versatile command-line utility designed to interact with the RIPE Database API. It allows users to perform detailed queries, filter specific fields, convert IP ranges to CIDR notation, and output the results in various formats. Additionally, it provides options to remove duplicate entries, ensuring clean and concise outputs tailored to your needs.

## Features

- **Search RIPE Database**: Perform full-text searches on the RIPE Database.
- **Field Filtering**: Extract and display only the fields you're interested in.
- **CIDR Conversion**: Convert IP ranges (`inetnum`) to CIDR notation
- **Multiple Output Formats**:
  - **Plain Text**: Simple and straightforward output.
  - **Table**: Structured tabular format for better readability.
  - **Grepable**: Output suitable for further text processing.
  - **JSON**: Structured data format for integration with other tools.
  - **XML**: Hierarchical data format for compatibility with various applications.
- **Deduplication**: Remove duplicate entries to ensure unique results.
- **Custom Separators**: Specify custom separators for output fields.
- **Output to Files**: Save results directly to files in your preferred format.

## Installation

### Prerequisites

- **Python 3.6+**: Ensure you have Python installed. You can download it from the [official website](https://www.python.org/downloads/).

### Clone the Repository

```bash
git clone https://github.com/rootsektor/ripe-api-query-tool.git
cd ripe-api-query-tool
```

### Install Dependencies

The tool relies on the following Python libraries:

- `requests`: For making HTTP requests to the RIPE API.
- `netaddr`: For handling and converting IP addresses and ranges.

You can install these dependencies using `pip`:

```bash
pip install -r requirements.txt
```

Alternatively, install them individually:

```bash
pip install requests netaddr
```

## Usage

The `ripe.py` script provides a range of options to customize your queries and outputs.

### Command-Line Arguments

| Argument        | Short Flag | Description                                                                                                                                         |
|-----------------|------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| `--query`       | `-q`       | **(Required)** The search string to use for the RIPE API query.                                                                                     |
| `--filter`      | `-f`       | Comma-separated list of fields to extract and include in the output. Available fields include: `inetnum`, `netname`, `person`, `admin-c`, `descr`, `country`, `status`, etc. |
| `--separator`   | `-s`       | Separator string for grepable and plain formats. Default is `,`.                                                                                   |
| `--output`      | `-o`       | Output file path where the results will be saved.                                                                                                  |
| `--output-type` | `-t`       | Output format: `plain`, `json`, `xml`. Default is `plain`.                                                                                        |
| `--table`       | `-T`       | Output results as a table.                                                                                                                           |
| `--grepable`    | `-g`       | Output results in a grepable format.                                                                                                                 |
| `--cidr`        | `-c`       | Convert subnet ranges (`inetnum`) to CIDR notation.                                                                                                 |
| `--unique`      | `-u`       | Remove duplicate entries from the output.                                                                                                            |
| `--help`        | `-h`       | Show help message and exit.                                                                                                                          |

### Examples

#### 1. Basic Usage (List Format - Default)

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum
```

**Description**: Searches for <search string> and displays the `inetnum` field in plain format.

#### 2. Basic Usage with CIDR Conversion

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum --cidr
```

**Description**: Searches for <search string>, extracts the `inetnum` field, and converts IP ranges to CIDR notation.

#### 3. Output as a Table

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum,netname --table
```

**Description**: Searches for <search string>, extracts the `inetnum` and `netname` fields, and displays the results in a table format.

#### 4. Output as a Table with CIDR Conversion

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum,netname --table --cidr
```

**Description**: Similar to the previous example but converts `inetnum` fields to CIDR notation.

#### 5. Grepable Format with Default Separator (Comma)

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum --grepable
```

**Description**: Outputs the `inetnum` field in a grepable format separated by commas.

#### 6. Grepable Format with Custom Separator (`;`)

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum --grepable --separator ";"
```

**Description**: Similar to the previous example but uses a semicolon (`;`) as the separator.

#### 7. Output to File in Plain Text

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --output targets.txt --output-type plain
```

**Description**: Saves the `netname` and `inetnum` fields to `targets.txt` in plain text format.

#### 8. Output to File in JSON

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --cidr --output targets.json --output-type json
```

**Description**: Saves the results to `targets.json` in JSON format with CIDR conversion applied.

#### 9. Output to File in XML

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --cidr --output targets.xml --output-type xml
```

**Description**: Saves the results to `targets.xml` in XML format with CIDR conversion applied.

#### 10. Remove Duplicates from Output

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --cidr --unique
```

**Description**: This command will search for <search string>, extract `netname` and `inetnum` fields, convert IP ranges to CIDR notation, and remove any duplicate entries from the final output.


### Examples

#### 1. Basic Usage (List Format - Default)

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum
```

**Description**: Searches for <search string> and displays the `inetnum` field in plain format.

#### 2. Basic Usage with CIDR Conversion

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum --cidr
```

**Description**: Searches for <search string>, extracts the `inetnum` field, and converts IP ranges to CIDR notation.

#### 3. Output as a Table

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum,netname --table
```

**Description**: Searches for <search string>, extracts the `inetnum` and `netname` fields, and displays the results in a table format.

#### 4. Output as a Table with CIDR Conversion

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum,netname --table --cidr
```

**Description**: Similar to the previous example but converts `inetnum` fields to CIDR notation.

#### 5. Grepable Format with Default Separator (Comma)

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum --grepable
```

**Description**: Outputs the `inetnum` field in a grepable format separated by commas.

#### 6. Grepable Format with Custom Separator (`;`)

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum --grepable --separator ";"
```

**Description**: Similar to the previous example but uses a semicolon (`;`) as the separator.

#### 7. Output to File in Plain Text

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --output targets.txt --output-type plain
```

**Description**: Saves the `netname` and `inetnum` fields to `targets.txt` in plain text format.

#### 8. Output to File in JSON

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --cidr --output targets.json --output-type json
```

**Description**: Saves the results to `targets.json` in JSON format with CIDR conversion applied.

#### 9. Output to File in XML

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --cidr --output targets.xml --output-type xml
```

**Description**: Saves the results to `targets.xml` in XML format with CIDR conversion applied.

#### 10. Remove Duplicates from Output

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --cidr --unique
```

**Description**: This command will search for <search string>, extract `netname` and `inetnum` fields, convert IP ranges to CIDR notation, and remove any duplicate entries from the final output.

#### 11. Full Output Without Filters

**Command**:

```bash
python3 ripe.py --query <search string>
```

**Description**: Displays all results for the query <search string> in a default list format without applying any filters.

### Examples with Outputs

#### 1. Basic Usage (List Format - Default)

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum
```

**Description**: Searches for <search string> and displays the `inetnum` field in plain format.

**Output**:

```
w.x.y.z - w.x.y.z
w.x.y.z - w.x.y.z
w.x.y.z - w.x.y.z
...
```

#### 2. Basic Usage with CIDR Conversion

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum --cidr
```

**Description**: Searches for <search string>, extracts the `inetnum` field, and converts IP ranges to CIDR notation.

**Output**:

```
w.x.y.z/28
w.x.y.z/29
w.x.y.z/29
...
```

#### 3. Output as a Table

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum,netname --table
```

**Description**: Searches for <search string>, extracts the `inetnum` and `netname` fields, and displays the results in a table format.

**Output**:

```
inetnum                | netname         
-----------------------+-----------------
w.x.y.z - w.x.y.z | NET-NAME1
w.x.y.z - w.x.y.z | NET-NAME2
...
```

#### 4. Grepable Format with Custom Separator (`;`)

**Command**:

```bash
python3 ripe.py --query <search string> --filter inetnum --grepable --separator ";"
```

**Description**: Outputs the `inetnum` field in a grepable format separated by semicolons.

**Output**:

```
w.x.y.z - w.x.y.z;
w.x.y.z - w.x.y.z;
w.x.y.z - w.x.y.z;
...
```

#### 5. Remove Duplicates from Output

**Command**:

```bash
python3 ripe.py --query <search string> --filter netname,inetnum --cidr --unique
```

**Description**: Searches for <search string>, extracts `netname` and `inetnum` fields, converts IP ranges to CIDR notation, and removes duplicates.

**Output**:

```
NET-NAME1,w.x.y.z/32
NET-NAME2,w.x.y.z/29
...
```

#### 6. Full Output Without Filters

**Command**:

```bash
python3 ripe.py --query <search string>
```

**Description**: Displays all results for the query <search string> in a default list format without applying any filters.

**Output**:

```
-----------------------------
inetnum: w.x.y.z - w.x.y.z
netname: NET-NAME1
person: John Doe
-----------------------------
inetnum: w.x.y.z - w.x.y.z
netname: NET-NAME2
person: Jane Smith
...
```
