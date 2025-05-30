#!/bin/bash

# Configuration
ILO_IP="YOUR_ILO_IP_ADDRESS"          # Replace with your ILO IP address
ILO_USERNAME="YOUR_ILO_USERNAME"      # Replace with your ILO username
ILO_PASSWORD="YOUR_ILO_PASSWORD"      # Replace with your ILO password
REDFISH_BASE_URI="/redfish/v1"

# Function to display usage
usage() {
    echo "Usage: $0"
    echo "This script fetches hardware health information from an ILO using Redfish."
    echo "It attempts to parse JSON without 'jq'. Please configure ILO_IP, ILO_USERNAME, and ILO_PASSWORD within the script."
    exit 1
}

# Check if configuration is set
if [ "$ILO_IP" == "YOUR_ILO_IP_ADDRESS" ] || \
   [ "$ILO_USERNAME" == "YOUR_ILO_USERNAME" ] || \
   [ "$ILO_PASSWORD" == "YOUR_ILO_PASSWORD" ]; then
    echo "Error: Please configure ILO_IP, ILO_USERNAME, and ILO_PASSWORD in the script."
    usage
fi

echo "Connecting to ILO at $ILO_IP..."

# Function to extract a value from JSON using grep/sed
# Arguments: JSON_STRING, KEY_PATH (e.g., "Status.Health")
extract_json_value() {
    local json_string="$1"
    local key_path="$2"
    local value=""

    # Split key_path into individual keys
    IFS='.' read -r -a keys <<< "$key_path"

    # Start with the full JSON string
    local current_scope="$json_string"

    for i in "${!keys[@]}"; do
        local key="${keys[$i]}"
        # For the last key, extract the value
        if [ "$i" -eq $(( ${#keys[@]} - 1 )) ]; then
            # Attempt to find the key and extract its value
            value=$(echo "$current_scope" | grep -oP "\"$key\"\s*:\s*\"?\K[^\",]+" | head -n 1)
            # Remove trailing quote if present for string values
            value=$(echo "$value" | sed 's/"$//')
        else
            # For intermediate keys, narrow down the scope to the object associated with the key
            # This is a very simplistic way to find an object and is highly prone to errors
            # if JSON structure isn't perfectly flat or if keys are not unique.
            local temp_scope=$(echo "$current_scope" | sed -n "/\"$key\":\s*{/,/}/p")
            if [ -z "$temp_scope" ]; then
                # Fallback to direct search if object not found (less reliable)
                 temp_scope=$(echo "$current_scope" | grep -oP "\"$key\"\s*:\s*{\K[^}]+" | head -n 1)
                 temp_scope="{${temp_scope}}" # Re-add braces for consistency
            fi
            current_scope="$temp_scope"
        fi
    done
    echo "$value"
}


---
### Overall System Health
SYSTEM_DATA=$(curl -s -k -u "${ILO_USERNAME}:${ILO_PASSWORD}" "https://${ILO_IP}${REDFISH_BASE_URI}/Systems/1")
OVERALL_HEALTH=$(echo "$SYSTEM_DATA" | grep -oP '"Health":\s*"\K[^"]+' | head -n 1)
OVERALL_STATE=$(echo "$SYSTEM_DATA" | grep -oP '"State":\s*"\K[^"]+' | head -n 1)

echo "Overall System Health: ${OVERALL_HEALTH:-N/A}" # Use N/A if empty
echo "Overall System State: ${OVERALL_STATE:-N/A}"

---
### Sensor Health (Temperatures, Fans, Power Supplies)
CHASSIS_URI=$(echo "$SYSTEM_DATA" | grep -oP '"Chassis":\s*{\s*"@odata.id":\s*"\K[^"]+' | head -n 1)

if [ -z "$CHASSIS_URI" ]; then
    echo "Could not find Chassis URI. Skipping detailed sensor health."
else
    CHASSIS_DATA=$(curl -s -k -u "${ILO_USERNAME}:${ILO_PASSWORD}" "https://${ILO_IP}${CHASSIS_URI}")

    echo -e "\n  -- Power Supplies --"
    # This is highly dependent on the JSON structure.
    # It assumes PowerSupplies is an array of objects directly under 'Power'.
    POWER_SUPPLY_NAMES=$(echo "$CHASSIS_DATA" | grep -oP '"PowerSupplies":\s*\[.*?\]' | grep -oP '"Name":\s*"\K[^"]+')
    POWER_SUPPLY_HEALTHS=$(echo "$CHASSIS_DATA" | grep -oP '"PowerSupplies":\s*\[.*?\]' | grep -oP '"Health":\s*"\K[^"]+')

    IFS=$'\n' read -r -a PS_NAMES_ARRAY <<< "$POWER_SUPPLY_NAMES"
    IFS=$'\n' read -r -a PS_HEALTHS_ARRAY <<< "$POWER_SUPPLY_HEALTHS"

    if [ ${#PS_NAMES_ARRAY[@]} -eq 0 ]; then
        echo "No power supply information found or not applicable."
    else
        for i in "${!PS_NAMES_ARRAY[@]}"; do
            echo "Name: ${PS_NAMES_ARRAY[$i]:-N/A} | Health: ${PS_HEALTHS_ARRAY[$i]:-N/A}"
        done
    fi

    echo -e "\n  -- Fans --"
    FAN_NAMES=$(echo "$CHASSIS_DATA" | grep -oP '"Fans":\s*\[.*?\]' | grep -oP '"Name":\s*"\K[^"]+')
    FAN_HEALTHS=$(echo "$CHASSIS_DATA" | grep -oP '"Fans":\s*\[.*?\]' | grep -oP '"Health":\s*"\K[^"]+')
    FAN_READINGS=$(echo "$CHASSIS_DATA" | grep -oP '"Fans":\s*\[.*?\]' | grep -oP '"Reading":\s*\K[0-9.]+')

    IFS=$'\n' read -r -a FAN_NAMES_ARRAY <<< "$FAN_NAMES"
    IFS=$'\n' read -r -a FAN_HEALTHS_ARRAY <<< "$FAN_HEALTHS"
    IFS=$'\n' read -r -a FAN_READINGS_ARRAY <<< "$FAN_READINGS"

    if [ ${#FAN_NAMES_ARRAY[@]} -eq 0 ]; then
        echo "No fan information found or not applicable."
    else
        for i in "${!FAN_NAMES_ARRAY[@]}"; do
            echo "Name: ${FAN_NAMES_ARRAY[$i]:-N/A} | Reading: ${FAN_READINGS_ARRAY[$i]:-N/A}RPM | Health: ${FAN_HEALTHS_ARRAY[$i]:-N/A}"
        done
    fi

    echo -e "\n  -- Temperatures --"
    TEMP_NAMES=$(echo "$CHASSIS_DATA" | grep -oP '"Temperatures":\s*\[.*?\]' | grep -oP '"Name":\s*"\K[^"]+')
    TEMP_HEALTHS=$(echo "$CHASSIS_DATA" | grep -oP '"Temperatures":\s*\[.*?\]' | grep -oP '"Health":\s*"\K[^"]+')
    TEMP_READINGS=$(echo "$CHASSIS_DATA" | grep -oP '"Temperatures":\s*\[.*?\]' | grep -oP '"ReadingCelsius":\s*\K[0-9.]+')

    IFS=$'\n' read -r -a TEMP_NAMES_ARRAY <<< "$TEMP_NAMES"
    IFS=$'\n' read -r -a TEMP_HEALTHS_ARRAY <<< "$TEMP_HEALTHS"
    IFS=$'\n' read -r -a TEMP_READINGS_ARRAY <<< "$TEMP_READINGS"

    if [ ${#TEMP_NAMES_ARRAY[@]} -eq 0 ]; then
        echo "No temperature information found or not applicable."
    else
        for i in "${!TEMP_NAMES_ARRAY[@]}"; do
            echo "Name: ${TEMP_NAMES_ARRAY[$i]:-N/A} | Reading: ${TEMP_READINGS_ARRAY[$i]:-N/A}C | Health: ${TEMP_HEALTHS_ARRAY[$i]:-N/A}"
        done
    fi
fi

---
### Memory Health
MEMORY_DATA=$(curl -s -k -u "${ILO_USERNAME}:${ILO_PASSWORD}" "https://${ILO_IP}${REDFISH_BASE_URI}/Systems/1/Memory")

MEMORY_LOCATORS=$(echo "$MEMORY_DATA" | grep -oP '"DeviceLocator":\s*"\K[^"]+')
MEMORY_HEALTHS=$(echo "$MEMORY_DATA" | grep -oP '"Health":\s*"\K[^"]+')
MEMORY_PARTNUMBERS=$(echo "$MEMORY_DATA" | grep -oP '"PartNumber":\s*"\K[^"]+')

IFS=$'\n' read -r -a MEM_LOC_ARRAY <<< "$MEMORY_LOCATORS"
IFS=$'\n' read -r -a MEM_HEALTHS_ARRAY <<< "$MEMORY_HEALTHS"
IFS=$'\n' read -r -a MEM_PARTNUMS_ARRAY <<< "$MEMORY_PARTNUMBERS"

if [ ${#MEM_LOC_ARRAY[@]} -eq 0 ]; then
    echo "No memory module information found."
else
    for i in "${!MEM_LOC_ARRAY[@]}"; do
        echo "Location: ${MEM_LOC_ARRAY[$i]:-N/A} | Health: ${MEM_HEALTHS_ARRAY[$i]:-N/A} | PartNumber: ${MEM_PARTNUMS_ARRAY[$i]:-N/A}"
    done
fi

---
### Storage Health
STORAGE_COLLECTION_DATA=$(curl -s -k -u "${ILO_USERNAME}:${ILO_PASSWORD}" "https://${ILO_IP}${REDFISH_BASE_URI}/Systems/1/Storage")

STORAGE_CONTROLLER_IDS=$(echo "$STORAGE_COLLECTION_DATA" | grep -oP '"@odata.id":\s*"\K/redfish/v1/Systems/1/Storage/[^"]+')

IFS=$'\n' read -r -a STORAGE_IDS_ARRAY <<< "$STORAGE_CONTROLLER_IDS"

if [ ${#STORAGE_IDS_ARRAY[@]} -eq 0 ]; then
    echo "No storage controller information found."
else
    for CONTROLLER_URI_PART in "${STORAGE_IDS_ARRAY[@]}"; do
        STORAGE_CONTROLLER_DATA=$(curl -s -k -u "${ILO_USERNAME}:${ILO_PASSWORD}" "https://${ILO_IP}${CONTROLLER_URI_PART}")

        CONTROLLER_NAME=$(echo "$STORAGE_CONTROLLER_DATA" | grep -oP '"Name":\s*"\K[^"]+' | head -n 1)
        CONTROLLER_HEALTH=$(echo "$STORAGE_CONTROLLER_DATA" | grep -oP '"Health":\s*"\K[^"]+' | head -n 1)

        echo "Controller: ${CONTROLLER_NAME:-N/A} | Health: ${CONTROLLER_HEALTH:-N/A}"

        # Try to find Volumes URI
        VOLUMES_URI_PART=$(echo "$STORAGE_CONTROLLER_DATA" | grep -oP '"Volumes":\s*{\s*"@odata.id":\s*"\K[^"]+' | head -n 1)

        if [ -n "$VOLUMES_URI_PART" ]; then
            VOLUMES_DATA=$(curl -s -k -u "${ILO_USERNAME}:${ILO_PASSWORD}" "https://${ILO_IP}${VOLUMES_URI_PART}")

            VOLUME_NAMES=$(echo "$VOLUMES_DATA" | grep -oP '"Name":\s*"\K[^"]+')
            VOLUME_HEALTHS=$(echo "$VOLUMES_DATA" | grep -oP '"Health":\s*"\K[^"]+')

            IFS=$'\n' read -r -a VOLUME_NAMES_ARRAY <<< "$VOLUME_NAMES"
            IFS=$'\n' read -r -a VOLUME_HEALTHS_ARRAY <<< "$VOLUME_HEALTHS"

            echo "  -- Logical Drives (Volumes) for ${CONTROLLER_NAME:-N/A} --"
            if [ ${#VOLUME_NAMES_ARRAY[@]} -eq 0 ]; then
                echo "  No logical drive (volume) information found for this controller."
            else
                for i in "${!VOLUME_NAMES_ARRAY[@]}"; do
                    echo "  Name: ${VOLUME_NAMES_ARRAY[$i]:-N/A} | Health: ${VOLUME_HEALTHS_ARRAY[$i]:-N/A}"
                done
            fi
        fi
    done
fi

echo -e "\nScript finished."