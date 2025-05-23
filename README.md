# artex-ExecutableMetadataScanner
Scans executable files (PE, ELF, Mach-O) to extract metadata such as compiler information, timestamps, imported libraries, and embedded resources.  Uses `pefile` (for PE), `lief` (for ELF/Mach-O), and `yara-python` to identify suspicious characteristics based on YARA rules. Outputs a report highlighting potential red flags. - Focused on Automated extraction of indicators of compromise (IOCs) and metadata from document and binary files. Focus on speed and accuracy, allowing quick triage of potentially malicious artifacts.

## Install
`git clone https://github.com/ShadowStrikeHQ/artex-executablemetadatascanner`

## Usage
`./artex-executablemetadatascanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-r`: No description provided
- `-o`: No description provided
- `-v`: Enable verbose logging

## License
Copyright (c) ShadowStrikeHQ
