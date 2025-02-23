#!/usr/bin/env python3
import json
import sys

def main():
    # Path to your JSON file
    input_file = "/tmp/ebpf_kovid.json"

    try:
        with open(input_file, "r") as f:
            data = json.load(f)  # data should be a list of JSON objects
    except Exception as e:
        print(f"Error reading {input_file}: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, list):
        print("Error: JSON file does not contain a top-level list.", file=sys.stderr)
        sys.exit(1)

    for obj in data:
        # 'obj' should be a dict with keys like "snapshot", "status", "len", etc.
        length_val = obj.get("len", 0)
        if length_val != 0:
            # Print only if len != 0
            print(json.dumps(obj, indent=2))

if __name__ == "__main__":
    main()
