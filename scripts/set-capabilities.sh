#!/bin/bash

if [ "${EUID}" != "0" ]; then
  echo "ERROR: must be root user"
  exit 1
fi

if [ -z "${1}" ]; then
  echo "ERROR: must supply file path to program to set Linux capabilities on"
  exit 1
fi

PROG_PATH="${1}"

setcap "cap_sys_admin=p cap_net_raw=p" "${PROG_PATH}"
getcap "${PROG_PATH}" 
