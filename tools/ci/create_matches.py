import argparse
from collections import defaultdict
import json
from posixpath import basename
from concurrent.futures import ThreadPoolExecutor as tpe
from typing import Iterator

import yara

from pathlib import Path
from plyara import Plyara

tags: dict = defaultdict(list)
final_matches: dict = defaultdict(list)


def get_yara_tags(yara_path: Path) -> dict[str, list[str]]:
    yara_files = get_yara_files(yara_path)
    result = dict()
    for yara_file in yara_files:
        print("> Get tags from ", yara_file)
        with open(yara_file) as f:
            plyara = Plyara()
            rules = plyara.parse_string(f.read())
            for rule in rules:
                if "tags" not in rule:
                    print("> [WARNING] No tags found in ", yara_file)
                result[rule["rule_name"]] = rule["tags"]
    return result


def get_yara_files(yara_dir: Path) -> list[Path]:
    return list(yara_dir.rglob("**/*.yar")) + list(yara_dir.rglob("**/*.yara"))


def get_yara_matches(yara_path: Path, samples_path: Path) -> dict[str, list[str]]:
    yara_files = get_yara_files(yara_path)
    if not yara_files:
        raise ValueError(f"> No YARA files found in {yara_path}")
    print(f"> Found {len(yara_files)} YARA files in {yara_path}")

    samples = [p for p in samples_path.rglob("*") if p.is_file()]
    if not samples:
        raise ValueError(f"> No samples found in {samples_path}")
    print(f"> Found {len(samples)} samples in {samples_path}")

    def get_matches(yara_file: Path) -> dict[str, list[str]]:
        matches = defaultdict(list)

        compiled = yara.compile(str(yara_file))
        print(f"> Checking matches on {basename(yara_file)}")
        for sample in samples:
            for m in compiled.match(str(sample)):
                matches[str(m)].append(basename(sample))

        return matches

    def get_results() -> Iterator[dict[str, list[str]]]:
        with tpe(max_workers=10) as executor:
            return executor.map(get_matches, yara_files)

    for partial_matches in get_results():
        for rule, m in partial_matches.items():
            final_matches[rule].extend(m)

    if not final_matches:
        raise ValueError("> No matches found")

    return final_matches


def write_json(matches: dict, filename: str):
    with open(filename, "w") as f:
        json.dump(matches, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--yara-path", "-y", type=str, default="./")
    parser.add_argument("--samples-path", "-s", type=str, default="./")
    parser.add_argument("--output", "-o", type=str, required=True)
    args = parser.parse_args()

    print("> Searching for matches")
    matches = get_yara_matches(Path(args.yara_path), Path(args.samples_path))
    print("> Writing matches into", args.output)
    write_json(matches, args.output)

    if "hardened" in args.output:
        print("> Getting tags")
        tags = get_yara_tags(Path(args.yara_path))
        tags_file = args.output.replace(".json", "_tags.json")
        print("> Writing tags into", tags_file)
        write_json(tags, tags_file)
