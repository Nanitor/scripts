#!/bin/bash

# Add your signup key:
SIGNUP_URL=''

# There is no need to change anything below, but read it anyway
INSTALLER_DIR='/tmp/nanitor-installer'
NANITOR_DATA_DIR="/Library/Application Support/Nanitor/Nanitor Agent"
NANITOR_DB_DIR="${NANITOR_DATA_DIR}/nanitor.db"

DOWNLOAD_NAME="nanitor-agent-latest_osx64.pkg"
DOWNLOAD_URL="https://nanitor.io/agents/temp$/{DOWNLOAD_NAME}"

if [ -e "${NANITOR_DB_DIR}" ]; then
    echo "Nanitor agent is already installed, do nothing"
    exit 0
fi

if [ -d "${INSTALLER_DIR}" ]; then
    rm -rf ${INSTALLER_DIR}
fi

mkdir -p "${INSTALLER_DIR}"
cd ${INSTALLER_DIR}
curl -o ${DOWNLOAD_NAME} ${DOWNLOAD_URL}

launchctl setenv nanitor_signup_url "${SIGNUP_URL}"
installer -pkg ./${DOWNLOAD_NAME} -target /Library/

echo "Nanitor agent was installed successfully"
exit 0
