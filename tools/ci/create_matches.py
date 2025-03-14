import argparse
from collections import defaultdict
import json
from posixpath import basename
from typing import Iterator
from concurrent.futures import ThreadPoolExecutor as tpe

import yara

from pathlib import Path


# def download_samples() -> Path:
#     tmp_dir = Path("tmp/matchingsamples")
#     if not tmp_dir.exists():
#         tmp_dir.mkdir(parents=True, exist_ok=True)

#         print("> Downloading samples")
#         session = Session()
#         client = session.client(service_name="s3")
#         zip = Path("tmp/samples.zip")
#         client.download_file("yara-matching-samples", "matchingsamples.zip", zip)

#         print("> Extracting samples")
#         with zipfile.ZipFile(zip, "r") as zip_ref:
#             zip_ref.extractall(tmp_dir, pwd=b"infected")

#     return tmp_dir


def get_yara_files(yara_dir: Path) -> list[Path]:
    return list(yara_dir.rglob("**/*.yar")) + list(yara_dir.rglob("**/*.yara"))


def get_yara_matches(yara_path: Path, samples_path: Path) -> dict[str, list[str]]:
    yara_files = get_yara_files(yara_path)
    samples = [p for p in samples_path.rglob("*") if p.is_file()]
    print(yara_files)

    def matches(yara_file: Path) -> dict:
        result = defaultdict(list)
        compiled = yara.compile(str(yara_file))
        print(f"> Checking matches on {basename(yara_file)}")
        for sample in samples:
            matches = compiled.match(str(sample))
            for m in matches:
                result[str(m)].append(basename(sample))
        return result

    def partial_results() -> Iterator[dict]:
        with tpe(max_workers=10) as executor:
            return executor.map(matches, yara_files)

    final_matches: dict[str, list[str]] = defaultdict(list)
    for partial_result in partial_results():
        for rule, partial_matches in partial_result.items():
            final_matches[rule].extend(partial_matches)
    return final_matches


def write_json(matches: dict, filename: str):
    with open(filename, "w") as f:
        json.dump(matches, f, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--yara-path", "-y", type=Path, default="./")
    parser.add_argument("--samples-path", "-s", type=Path, default="./")
    parser.add_argument("--output", "-o", type=Path, required=True)
    args = parser.parse_args()

    print("> Searching for matches")
    matches = get_yara_matches(args.yara_path, args.samples_path)
    print("> Writing matches into", args.output)
    write_json(matches, args.output)
