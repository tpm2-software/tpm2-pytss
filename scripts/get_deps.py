#!/usr/bin/env python3

import argparse
import configparser


def main():

    parser = argparse.ArgumentParser(
        description="Dumps requred dependencies from a setup.cfg file"
    )
    parser.add_argument("filename", nargs="?", default="setup.cfg")
    args = parser.parse_args()

    c = configparser.ConfigParser()
    c.read(args.filename)
    packages = c["options"]["setup_requires"].replace("\n", " ").strip()
    packages += " " + c["options"]["install_requires"].replace("\n", " ").strip()
    print(packages)


if __name__ == "__main__":
    main()
