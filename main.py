import argparse
import logging
import os
import sys
import json

try:
    import pefile
    import lief
    import yara
except ImportError as e:
    print(f"Error: Missing dependencies. Please install them:\n{e}")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class ExecutableMetadataScanner:
    """
    Scans executable files to extract metadata and identify suspicious characteristics.
    """

    def __init__(self, filepath, yara_rules_path=None):
        """
        Initializes the scanner.

        Args:
            filepath (str): Path to the executable file.
            yara_rules_path (str, optional): Path to the YARA rules file. Defaults to None.
        """
        self.filepath = filepath
        self.yara_rules_path = yara_rules_path
        self.report = {}

    def _load_yara_rules(self):
        """
        Loads YARA rules from the specified file.

        Returns:
            yara.Rules: Compiled YARA rules or None if loading fails.
        """
        if not self.yara_rules_path:
            return None

        try:
            rules = yara.compile(filepath=self.yara_rules_path)
            return rules
        except yara.Error as e:
            logging.error(f"Error compiling YARA rules: {e}")
            return None

    def scan(self):
        """
        Performs the scan and generates a report.
        """
        try:
            self.report['file_path'] = self.filepath
            self.report['file_size'] = os.path.getsize(self.filepath)

            # Determine file type and scan accordingly
            with open(self.filepath, 'rb') as f:
                header = f.read(4)
                if header.startswith(b'MZ'):
                    self._scan_pe()
                elif header.startswith(b'\x7fELF'):
                    self._scan_elf()
                elif header.startswith(b'\xFE\xED\xFA\xCF') or header.startswith(b'\xCF\xFA\xED\xFE') or header.startswith(b'\xFE\xED\xFE\xCF'):
                    self._scan_mach_o() # Added checks for various Mach-O headers.
                else:
                    self.report['error'] = "Unsupported file type"
                    logging.warning(f"Unsupported file type for: {self.filepath}")
                    return

            # Run YARA rules if provided
            if self.yara_rules_path:
                rules = self._load_yara_rules()
                if rules:
                    try:
                        with open(self.filepath, 'rb') as f:
                            matches = rules.match(data=f.read())
                            self.report['yara_matches'] = [match.rule for match in matches]
                    except Exception as e:
                        logging.error(f"Error running YARA rules: {e}")
                        self.report['yara_error'] = str(e)

        except FileNotFoundError:
            self.report['error'] = "File not found"
            logging.error(f"File not found: {self.filepath}")
        except Exception as e:
            self.report['error'] = f"An unexpected error occurred: {e}"
            logging.exception(f"An unexpected error occurred while scanning: {self.filepath}")
        finally:
            return self.report

    def _scan_pe(self):
        """
        Scans a PE file.
        """
        try:
            pe = pefile.PE(self.filepath)

            self.report['file_type'] = 'PE'
            self.report['timestamp'] = pe.FILE_HEADER.TimeDateStamp
            self.report['compiler'] = self._get_compiler_info_pe(pe)
            self.report['imported_libraries'] = [dll.decode('utf-8', 'ignore') for dll in pe.get_libraries()]
            self.report['number_of_sections'] = pe.FILE_HEADER.NumberOfSections

            # Extract resources
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                try:
                    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                        resources.append({
                                            'type': str(resource_type.struct.Id),
                                            'id': str(resource_id.struct.Id),
                                            'lang': str(resource_lang.struct.Id),
                                            'size': resource_lang.data.struct.Size,
                                            'data': data.hex() if len(data) < 256 else f'Size too large to display' # limit resource data output for large files.
                                        })
                except Exception as e:
                    logging.warning(f"Error extracting PE resources: {e}")

            self.report['resources'] = resources
            pe.close()  # Close the PE file object to release resources

        except pefile.PEFormatError as e:
            self.report['error'] = f"PE format error: {e}"
            logging.error(f"PE format error: {e} - {self.filepath}")
        except Exception as e:
            self.report['error'] = f"Error scanning PE file: {e}"
            logging.error(f"Error scanning PE file: {e} - {self.filepath}")

    def _scan_elf(self):
        """
        Scans an ELF file.
        """
        try:
            binary = lief.parse(self.filepath)

            if binary is None:
                self.report['error'] = "Failed to parse ELF file"
                logging.error(f"Failed to parse ELF file: {self.filepath}")
                return

            self.report['file_type'] = 'ELF'
            self.report['entry_point'] = binary.entrypoint
            self.report['imported_libraries'] = [lib.name for lib in binary.libraries]
            self.report['is_pie'] = binary.has_nx()

        except lief.parser_error as e:
            self.report['error'] = f"LIEF parser error: {e}"
            logging.error(f"LIEF parser error: {e} - {self.filepath}")
        except Exception as e:
            self.report['error'] = f"Error scanning ELF file: {e}"
            logging.error(f"Error scanning ELF file: {e} - {self.filepath}")


    def _scan_mach_o(self):
        """
        Scans a Mach-O file.
        """
        try:
            binary = lief.parse(self.filepath)

            if binary is None:
                self.report['error'] = "Failed to parse Mach-O file"
                logging.error(f"Failed to parse Mach-O file: {self.filepath}")
                return

            self.report['file_type'] = 'Mach-O'
            self.report['entry_point'] = binary.entrypoint
            self.report['imported_libraries'] = [lib.name for lib in binary.libraries]
            self.report['is_pie'] = binary.has_nx()

        except lief.lief_errors.parser_error as e:
             self.report['error'] = f"LIEF parser error: {e}"
             logging.error(f"LIEF parser error: {e} - {self.filepath}")

        except Exception as e:
            self.report['error'] = f"Error scanning Mach-O file: {e}"
            logging.error(f"Error scanning Mach-O file: {e} - {self.filepath}")

    def _get_compiler_info_pe(self, pe):
        """
        Attempts to determine the compiler used to build the PE file.

        Args:
            pe (pefile.PE): pefile object.

        Returns:
            str: Compiler information if found, otherwise None.
        """
        try:
            if hasattr(pe, 'VS_VERSIONINFO'):
                if hasattr(pe.VS_VERSIONINFO, 'StringFileInfo'):
                    for string_info in pe.VS_VERSIONINFO.StringFileInfo:
                        for str_table in string_info.StringTable:
                            for key, value in str_table.entries.items():
                                if key == 'CompanyName' and 'Microsoft' in value:
                                    return 'Microsoft Visual C/C++'
                                elif key == 'FileDescription' and 'Borland' in value:
                                    return 'Borland Compiler'
            return None
        except Exception as e:
            logging.warning(f"Error getting compiler info: {e}")
            return None

def setup_argparse():
    """
    Sets up the argument parser.

    Returns:
        argparse.ArgumentParser: Argument parser object.
    """
    parser = argparse.ArgumentParser(description="Scans executable files for metadata and suspicious characteristics.")
    parser.add_argument("filepath", help="Path to the executable file")
    parser.add_argument("-r", "--yara_rules", help="Path to YARA rules file (optional)")
    parser.add_argument("-o", "--output", help="Path to save the JSON report (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    return parser

def main():
    """
    Main function.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Input validation
    if not os.path.isfile(args.filepath):
        logging.error(f"Error: File not found: {args.filepath}")
        sys.exit(1)

    if args.yara_rules and not os.path.isfile(args.yara_rules):
        logging.error(f"Error: YARA rules file not found: {args.yara_rules}")
        sys.exit(1)

    scanner = ExecutableMetadataScanner(args.filepath, args.yara_rules)
    report = scanner.scan()

    if args.output:
        try:
            with open(args.output, 'w') as outfile:
                json.dump(report, outfile, indent=4)
            logging.info(f"Report saved to: {args.output}")
        except Exception as e:
            logging.error(f"Error saving report to file: {e}")
    else:
        print(json.dumps(report, indent=4))

if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Scan a PE file:
#    python artex_ExecutableMetadataScanner.py malware.exe
#
# 2. Scan a PE file with YARA rules and save the report to a file:
#    python artex_ExecutableMetadataScanner.py malware.exe -r malware_rules.yara -o malware_report.json
#
# 3. Enable verbose logging:
#    python artex_ExecutableMetadataScanner.py malware.exe -v

# Offensive Tools:
# This tool can be used to quickly analyze potentially malicious executables.
# YARA rules can be written to detect specific packing techniques, known malware signatures,
# or other suspicious characteristics.  The extracted metadata (imported libraries, timestamps, etc.)
# can be used to generate IOCs for threat intelligence purposes.