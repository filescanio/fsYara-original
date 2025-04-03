import argparse
import json
from pathlib import Path


def check_matches(o: Path, h: Path, ht: Path):
    original = json.load(open(o))
    hardened = json.load(open(h))
    hardened_tags = json.load(open(ht))

    print("> Create errors list")
    errors: dict = dict()
    limited_errors: dict = dict()

    for original_rule, original_matches in original.items():
        hardened_matches = hardened.get(original_rule, [])

        for original_match in original_matches:
            if original_match in hardened_matches:
                continue

            if "limited" in hardened_tags[original_rule]:
                append_error(limited_errors, original_rule, original_match, "missing")
            else:
                append_error(errors, original_rule, original_match, "missing")

    for hardened_rule, hardened_matches in hardened.items():
        original_matches = original.get(hardened_rule, [])
        for hardened_match in hardened_matches:
            if hardened_match in original_matches:
                continue
            if "limited" in hardened_tags[hardened_rule]:
                append_error(limited_errors, hardened_rule, hardened_match, "extra")
            else:
                append_error(errors, hardened_rule, hardened_match, "extra")

    if errors:
        print("> [WARNING] Found deviations in matches, details in errors.json")
        print("> Write errors list")
        write_json(errors, "errors.json")
        write_json(limited_errors, "limited_errors.json")
    else:
        print("> SUCCESS")


def append_error(errors: dict, rule: str, match: str, error_type: str):
    if rule not in errors:
        errors[rule] = dict()
    if error_type not in errors[rule]:
        errors[rule][error_type] = []

    errors[rule][error_type].append(match)


def write_json(matches: dict, filename: str):
    with open(filename, "w") as f:
        json.dump(matches, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", "-o", type=str, required=True)
    parser.add_argument("--hardened", "-H", type=str, required=True)
    args = parser.parse_args()

    check_matches(
        Path(args.original),
        Path(args.hardened),
        Path(args.hardened.replace(".json", "_tags.json")),
    )
