import os
import re
import argparse
import logging
import sys
import plyara
from plyara.utils import rebuild_yara_rule


# https://yara.readthedocs.io/en/v3.4.0/writingrules.html#text-strings
def escape_yara(s: str) -> bytes:
    s = s.encode()

    # Replace encoded hex characters
    s = re.sub(rb'(?<!\\)\\x([a-fA-F0-9]{2})', lambda m: bytes([int(m.group(1), 16)]), s)

    # Replace double quote escapes (\")
    s = re.sub(rb'(?<!\\)\\"', b'"', s)

    # Replace tab escapes (\t)
    s = re.sub(rb'(?<!\\)\\t', b'\t', s)

    # Replace newline escapes (\n)
    s = re.sub(rb'(?<!\\)\\n', b'\n', s)

    # Replace escaped backslashes (\\ → \)
    # s = re.sub(rb'\\\\', b'\\', s)
    s = s.replace(b'\\\\', b'\\')

    return s


def string_to_hex_array(s, is_wide, is_ascii, is_nocase, is_xor, xor_vals, is_fullword):
    def to_hex(b):
        return f"{b:02x}"
    
    def ascii_encoding(char: int) -> str:
        if not is_nocase:
            return to_hex(char)
        
        try:
            decoded_char = chr(char)
            if (char < 0 or char > 127) or len(decoded_char) > 1:
                raise "Wrong decode"

            # upper or lowercasing may produce longer than 1 character things, good example is ß
            lower = to_hex(ord(decoded_char.lower()) if len(decoded_char.lower()) == 1 else decoded_char)
            upper = to_hex(ord(decoded_char.upper()) if len(decoded_char.upper()) == 1 else decoded_char)
        except:
            return to_hex(char)

        return f"({lower} | {upper})" if lower != upper else lower


    def wide_encoding(char: bytes):
        if not is_nocase:
            return to_hex(char) + " 00"
        try:
            decoded_char = chr(char)
            if (char < 0 or char > 127) or len(decoded_char) > 1:
                raise "Wrong decode"
            
            # upper or lowercasing may produce longer than 1 character things, good example is ß
            lower = to_hex(ord(decoded_char.lower()) if len(decoded_char.lower()) == 1 else decoded_char)
            upper = to_hex(ord(decoded_char.upper()) if len(decoded_char.upper()) == 1 else decoded_char)
        except:
            return to_hex(char) + " 00"

        return f"({lower} | {upper}) 00" if lower != upper else lower + " 00"
    

    def xor_encoding(xormin, xormax):
        max_or = 60
        #note that yara does not allow to combine xor with nocase, so no need to consider nocase
        if xormax - xormin > max_or: # cant include all xored values, too large
            xormax = xormin + max_or
            if is_wide and is_ascii:
                xormax = xormin + max_or/2
            logging.warning(f"[Rule warning] xored limited to {max_or} xor key values for string: " + str(s))
            logging.warning(f"[Rule warning] The rule may low slow down scanning" + str(s))
        cur = xormin
        ret_str = ""
        ret_str_wide = ""
        try:
            while cur <= xormax:
                ret_str = f"{ret_str}("
                ret_str_wide = f"{ret_str_wide}("
                for c in s:
                    xored_char = c ^ cur
                    if is_ascii:
                        ret_str = f"{ret_str} {xored_char:02x}"
                    if is_wide:
                        ret_str_wide = f"{ret_str_wide} {xored_char:02x} {cur:02x}"
                if is_ascii:
                    ret_str = f"{ret_str}) |"
                if is_wide:
                  ret_str_wide = f"{ret_str_wide}) |"
                cur += 1
        except:
            pass

        if is_ascii:
            if is_wide:
                return f"{ret_str[:-1]} | {ret_str_wide[:-1]}" # ascii and wide
            return f"{ret_str[:-1]}" # only ascii
        else:
            return f"{ret_str_wide[:-1]}" #only wide


    s = escape_yara(s)

    # Such cases may lead into regex complexity issues!
    if is_ascii and is_wide and is_nocase and len(s) > 72:
        is_nocase = False
        logging.warning("[Rule warning] the rule may run into regex complexity issues: " + str(s))

    xored_parts = xor_encoding(xor_vals[0], xor_vals[1]) if is_xor else ""

    if is_xor and xored_parts:
        # Need to convert to wide if necessary
        return f"({xored_parts})" # If the xor mod is used, we do not care about returning the plaintext ascii/wide

    ascii_part = " ".join(ascii_encoding(c) for c in s) if is_ascii else ""
    wide_part = " ".join(wide_encoding(c) for c in s) if is_wide else ""

    if is_fullword:
        ascii_delimit = "(bf | a1 | 21 | 22 | 23 | 24 | 25 | 26 | 27 | 28 | 29 | 2a | 2b | 2c | 2d | 2e | 2f | 3a | 3b | 3c | 3d | 3e | 3f | 40 | 5b | 5c | 5d | 5e | 5f | 60 | 7b | 7c | 7d | 7e | 20 | 09 | 0a | 0d | 0b | 0c | 00 | ff)"
        wide_delimit = "(bf 00 | a1 00 | 21 00 | 22 00 | 23 00 | 24 00 | 25 00 | 26 00 | 27 00 | 28 00 | 29 00 | 2a 00 | 2b 00 | 2c 00 | 2d 00 | 2e 00 | 2f 00 | 3a 00 | 3b 00 | 3c 00 | 3d 00 | 3e 00 | 3f 00 | 40 00 | 5b 00 | 5c 00 | 5d 00 | 5e 00 | 5f 00 | 60 00 | 7b 00 | 7c 00 | 7d 00 | 7e 00 | 20 00 | 09 00 | 0a 00 | 0d 00 | 0b 00 | 0c 00 | 00 00 | ff)"
        if is_ascii:
            ascii_part = f"{ascii_delimit} {ascii_part} {ascii_delimit}"
        if is_wide:
            wide_part = f"{wide_delimit} {wide_part} {wide_delimit}"

    if is_ascii and is_wide:
        return f"(({ascii_part}) | ({wide_part}))"


    return ascii_part or wide_part


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
        return hex_ruleset, success

    for rule in rules:
        try:
            loosen = False
            # Remove comments from metadata
            # Note that the parser removes already all the comments (including multiline ones) by itself
            if strip_comments and 'comments' in rule:
                del rule['comments']


            is_limited = False

            # Convert string to hex
            if 'strings' in rule:
                for string in rule['strings']:
                    if 'type' in string and 'text' in string['type']:
                        if 'value' in string:
                            is_wide, is_ascii, is_nocase, is_xor, is_fullword = False, False, False, False, False
                            xor_vals = None
                            if 'modifiers' in string:
                                is_wide = 'wide' in string['modifiers']
                                is_ascii = 'ascii' in string['modifiers']
                                is_nocase = 'nocase' in string['modifiers']
                                is_fullword = 'fullword' in string['modifiers']

                                if any(x not in {"wide", "ascii", "private"} for x in string['modifiers']):
                                    # xor will be always marked as limited, even though in some cases may not he limited
                                    is_limited = True

                                if not is_wide and not is_ascii:
                                    is_ascii = True

                                if is_ascii and is_wide and is_fullword:
                                    # It will be limited in the sense that it will match extra files instead of missing matches
                                    # So it is a more loose rule / less strict, for ignoring the fullword modifier
                                    loosen = True
                                    is_fullword = False

                                try:
                                    for mod in string['modifiers']:
                                        if "xor" in mod:
                                            is_xor = True
                                            if "xor" == mod:
                                                xor_vals = (0, 255)
                                                break
                                            else:
                                                xor_pattern = r"xor\( *(0x[0-9A-Fa-f]{2}) *- *(0x[0-9A-Fa-f]{2} *)\)"
                                                match = re.search(xor_pattern, mod)
                                                if match:
                                                    xor_vals = (int(match.group(1), 16), int(match.group(2), 16))
                                                    break
                                                else:
                                                    is_xor = False # This should not be possible anyway at this point, but just in case
                                except:
                                    logging.error("[Hardening error] Error when parsing xor modifier")
                                    raise "Error parsing xor modifier"


                                del string['modifiers']
                            else: # No modifiers at all => ascii
                                is_ascii = True
                            hex_string = string_to_hex_array(string['value'], is_wide, is_ascii, False, is_xor, xor_vals, is_fullword)
                            if hex_string:
                                old_value = string['value']
                                string['value'] = f'{{{hex_string}}}'
                                string['type'] = 'hex'
                                logging.info(f"[{rule['rule_name']}][{string['name']}] Converted string (ascii: {is_ascii}, wide: {is_wide}, nocase: {is_nocase}) to hex: {old_value} -> {string['value']}")

            # add hardened tag
            tags = []
            if 'tags' in rule:
                tags = rule['tags']
            tags.append('hardened')
            if loosen:
                tags.append('loosened')

            # nocase        -> PARTIALLY_HANDLED (Disabled due to regex complexity)
            # wide          -> HANDLED
            # ascii         -> HANDLED
            # xor           -> PARTIALLY_HANDLED (restricted number of xor keys)
            # base64        -> NO SUPPORT
            # base64wide    -> NO SUPPORT
            # fullword      -> PARTIALLY_HANDLED - limited
            # private       -> NO SUPPORT (IGNORED from limited)
            if is_limited:
                logging.warning(f"[{rule['rule_name']}] is limited in capabilities due to special string modifier")
                tags.append('limited')
            rule['tags'] = tags


            # add hardened yara rule
            hex_ruleset += rebuild_yara_rule(rule, condition_indents=False) + '\n'
        except Exception as e:
            # error hardening a yara rule
            # only drop problematic yara rule, not the yara ruleset
            if rule and 'rule_name' in rule:
                #print(e)
                logging.error(f"[Hardening error] Erroneous yara rule {rule['rule_name']} may contain invalid YARA syntax")
                success = False

    # test hardened yara ruleset
    yara_parser = plyara.Plyara() # reset
    try:
        yara_parser.parse_string(hex_ruleset)
    except:
        # invalid yara ruleset
        logging.error("[Hardening error] Invalid YARA syntax after hardening")
        success = False
        #hex_ruleset = "// Content could not be hardened properly" # leave a comment in the yara file

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
    if not os.path.isdir(input_folder):
        print(f"Input folder does not exist!")
        return
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
        logging.error("Yara hardening process failed for at least one rule!")
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
