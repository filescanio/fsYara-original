import os
import argparse
import logging
import sys
import plyara
from plyara.utils import rebuild_yara_rule


def string_to_hex_array(s, encoding='ascii'):
    if 'ascii&wide' in encoding:
        return "( " + " ".join(f"{ord(c):02X}" for c in s) + " | " + " 00 ".join(f"{ord(c):02X}" for c in s) + " 00" + " )"
    if 'ascii' in encoding:
        return " ".join(f"{ord(c):02X}" for c in s)
    if 'wide' in encoding:
        return " 00 ".join(f"{ord(c):02X}" for c in s) + " 00"




def process_yara_ruleset(yara_ruleset, strip_comments=True):
    hex_ruleset = ''
    success = True
    yara_parser = plyara.Plyara()
    try:
        rules = yara_parser.parse_string(yara_ruleset)
    except:
        # invalid yara ruleset
        logging.error("[Parsing error] Invalid YARA syntax")
        success = False
        hex_ruleset = "// Removed content due to invalid YARA syntax" # leave a comment in the yara file
        return hex_ruleset

    for rule in rules:
        try:
            # Remove comments from metadata
            # Note that the parser removes already all the comments (including multiline ones) by itself
            if strip_comments and 'comments' in rule:
                del rule['comments']

            # Convert string to hex
            if 'strings' in rule:
                for string in rule['strings']:
                    if 'type' in string and 'text' in string['type']:
                        if 'value' in string:
                            wide, ascii = False, False
                            if 'modifiers' in string:
                                wide = 'wide' in string['modifiers']
                                ascii = 'ascii' in string['modifiers']
                                del string['modifiers']
                            if ascii and wide:
                                encoding = 'ascii&wide'
                            elif ascii:
                                encoding = 'ascii'
                            elif wide:
                                encoding = 'wide'
                            else:  # ascii by default when no keywords
                                encoding = 'ascii'
                            hex_string = string_to_hex_array(string['value'], encoding=encoding)
                            if hex_string:
                                old_value = string['value']
                                string['value'] = f'{{{hex_string}}}'
                                string['type'] = 'hex'
                                logging.info(f"[{rule['rule_name']}][{string['name']}] Converted string (encoding: {encoding}) to hex: {old_value} -> {string['value']}")

            # add hardened yara rule
            hex_ruleset += rebuild_yara_rule(rule, condition_indents=False) + '\n'
        except:
            # error hardening a yara rule
            # only drop problematic yara rule, not the yara ruleset
            if rule and 'rule_name' in rule:
                logging.error(f"[Hardening error] Erroneous yara rule {rule['rule_name']} containing invalid YARA syntax")
                success = False

    # test hardened yara ruleset
    yara_parser = plyara.Plyara() # reset
    try:
        yara_parser.parse_string(hex_ruleset)
    except:
        # invalid yara ruleset
        logging.error("[Hardening error] Invalid YARA syntax after hardening")
        success = False
        hex_ruleset = "// Content could not be hardened properly" # leave a comment in the yara file

    return hex_ruleset, success

def process_file(ruleset, input_file, output_file, strip_comments=True):
    success = False
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            ruleset_content = infile.read()
    except UnicodeDecodeError:
        with open(input_file, 'r', encoding='ISO-8859-1') as infile:
            ruleset_content = infile.read()

    if ruleset_content:
        logging.info(f"Modifications in ruleset: {ruleset}")
        converted_yara_ruleset, success = process_yara_ruleset(ruleset_content, strip_comments=strip_comments)

        # always overwrite, since parser removes unnecessary stuff
        if converted_yara_ruleset:
            with open(output_file, 'w', encoding='utf-8') as outfile:
                outfile.write(converted_yara_ruleset)
            
    return success
        
def traverse_and_process(input_folder, output_prefix=None, strip_comments=True):
    hardening_success = True
    for root, _, files in os.walk(input_folder):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                input_file_path = os.path.join(root, file)
                if output_prefix:
                    output_file_path = os.path.join(root, output_prefix + file)
                    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
                else:
                    output_file_path = input_file_path

                processing_result = process_file(file, input_file_path, output_file_path, strip_comments)
                if not processing_result:
                    logging.error(f"Hardening error occurred for file: {input_file_path}")
                    hardening_success = False
    
    if hardening_success:
        print(f"Yara hardening process completed successfully!")
    else:
        logging.error("Yara hardening process failed!")
        sys.exit(1)

def delete_files_in_yara_folder(root_dir):
    # Walk through the directory tree
    for root, dirs, files in os.walk(root_dir):
        # Check if 'yara' is in the path
        if 'yara' in root.lower():
            for file in files:
                # Check for specific file extensions (unneeded artefacts)
                if file.endswith(('.eml', '.csv', '.txt', '.js')):
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                        print(f"Deleted: {file_path}")
                    except Exception as e:
                        print(f"Failed to delete {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Clean YARA rules to avoid AV detection by converting ASCII strings to hex arrays and stripping comments, deleting unneeded artefacts (optional, enabled by default).")
    parser.add_argument("input_folder", help="Path to the input folder containing YARA rule files.")
    parser.add_argument("--output-prefix", help="Optional prefix for output files. If not provided, original files are overwritten.", default=None)
    parser.add_argument("--strip-comments", action="store_true", help="Strip comments from the entire rule (default: True).", default=True)
    parser.add_argument("--delete-unneeded-artefacts", dest="delete_artefacts", action="store_true", default=True,
                        help="Delete .eml, .csv, and .txt files in folders containing 'yara'. Default is True.")
    parser.add_argument("--keep-unneeded-artefacts", dest="delete_artefacts", action="store_false",
                        help="Do not delete .eml, .csv, and .txt files even if folders contain 'yara'.")
    parser.add_argument('--verbose', '-v', action='count', default=1)

    args = parser.parse_args()

    args.verbose = 40 - (10*args.verbose) if args.verbose > 0 else 0
    logging.basicConfig(level=args.verbose, format='%(asctime)s %(levelname)s: %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    traverse_and_process(args.input_folder, output_prefix=args.output_prefix, strip_comments=args.strip_comments)

    if args.delete_artefacts:
        delete_files_in_yara_folder(args.input_folder)


if __name__ == "__main__":
    main()
