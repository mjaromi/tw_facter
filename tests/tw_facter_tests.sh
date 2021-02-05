#!/usr/bin/bash

if ! command -v jq &>/dev/null; then
    echo "${command} NOT FOUND in the PATH"
    exit 1
fi

for kind in appliance cluster custom cores discovery env facter jdbc metadata omninames options rpms security services system taxonomy users vault windows ; do
    if tw_facter -d -k ${kind} &>/dev/null; then
        echo "Test for kind '${kind}' PASSED"
    else
        echo "Test for kind '${kind}' FAILED"
    fi
done
