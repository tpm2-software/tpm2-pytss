#!/bin/sh

usage () {
    echo "Usage: $0 [-c|--check] [-h|--help] [PATH]"
}

DIR=$(pwd)
CHECK=YES
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
    -c|--check)
        CHECK=true
        shift
        ;;
    -h|--help)
        usage
        exit 0
        shift
        ;;
    -*)
        echo Unknown parameter "$1"
        usage
        exit 1
        ;;
    *)
        # does not check if multiple positionals were given
        DIR="$1"
        shift
        ;;
    esac
done

check_black=""
check_isort=""
if [ "${CHECK}" = true ]; then
    check_black="--diff --check"
    check_isort="--diff --check-only"
fi

python -m black ${check_black} "${DIR}"
python -m isort ${check_isort} "${DIR}"