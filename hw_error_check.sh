#!/bin/bash

YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

DISKS=$(lsblk -dn -o NAME,TYPE | grep 'disk\|nvme' | awk '{print "/dev/"$1}')

for DISK in $DISKS; do
  SMART_DATA=$(sudo smartctl -a $DISK)

  DEVICE_MODEL=$(echo "$SMART_DATA" | grep -i "Device Model" | awk -F: '{print $2}' | xargs)
  if [ -z "$DEVICE_MODEL" ]; then
    DEVICE_MODEL=$(echo "$SMART_DATA" | grep -i "Model Number" | awk -F: '{print $2}' | xargs)
  fi
  
  if echo "$DEVICE_MODEL" | grep -q "SSD"; then
    echo -e "${YELLOW}S.M.A.R.T Attribute Values for $DISK (SSD):${NC}"
    health_status=$(echo "$SMART_DATA" | grep -i "SMART overall-health self-assessment test result" | awk '{print $6}')
    reallocated_sector_count=$(echo "$SMART_DATA" | grep -i "Reallocated_Sector_Ct" | awk '{print $10}')
    power_on_hours=$(echo "$SMART_DATA" | grep -i "Power_On_Hours" | awk '{print $10}')
    wear_leveling_count=$(echo "$SMART_DATA" | grep -i "Wear_Leveling_Count" | awk '{print $10}')
    total_lbas_written=$(echo "$SMART_DATA" | grep -i "Total_LBAs_Written" | awk '{print $10}')
    
    max_wear_leveling_count=100
    remaining_life_percent=$(awk "BEGIN {printf \"%.2f\", (1 - $wear_leveling_count / $max_wear_leveling_count) * 100}")

    total_lbas_written_gb=$(awk "BEGIN {printf \"%.2f\", $total_lbas_written * 512 / (1024^3)}")

        display_value() {
          name=$1
          value=$2
          if [ -n "$value" ]; then
            if [ "$name" == "Health Status" ]; then
              if [ "$value" == "PASSED" ]; then
                printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
              else
                printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
              fi
            elif [ "$name" == "Remaining Life (%)" ]; then
              if (( $(echo "$value == 30.00" | bc -l) )); then
                printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
              else
                printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
              fi
           elif [ "$name" == "Wear Leveling Count" ]; then
             if (( $(echo "$value >= 500" | bc -l) )); then
               printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
             else
               printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
             fi
            elif [ -z "$value" ] || [ "$value" == "-" ]; then
              printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
            elif [ "$value" -eq "$value" ] 2>/dev/null; then
              if [ "$value" -eq 0 ]; then
                printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
              else
                printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
              fi
            else
              printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
            fi
          fi
        }

    display_value "Health Status" "$health_status"
    display_value "Reallocated Sector Count" "$reallocated_sector_count"
    display_value "Power On Hours" "$power_on_hours"
    display_value "Wear Leveling Count" "$wear_leveling_count"
    display_value "Remaining Life (%)" "$remaining_life_percent"
    display_value "Total LBAs Written (GB)" "$total_lbas_written_gb"
    echo "--------------------------------------"

  elif echo "$DEVICE_MODEL" | grep -q "^ST"; then
    echo -e "${YELLOW}S.M.A.R.T Attribute Values for $DISK (SATA):${NC}"
    RAW_READ_ERROR_RATE=$(echo "$SMART_DATA" | grep "Raw_Read_Error_Rate")
    REALLOCATED_SECTOR_CT=$(echo "$SMART_DATA" | grep "Reallocated_Sector_Ct")
    SEEK_ERROR_RATE=$(echo "$SMART_DATA" | grep "Seek_Error_Rate")
    SPIN_RETRY_COUNT=$(echo "$SMART_DATA" | grep "Spin_Retry_Count")
    CURRENT_PENDING_SECTOR=$(echo "$SMART_DATA" | grep "Current_Pending_Sector")
    OFFLINE_UNCORRECTABLE=$(echo "$SMART_DATA" | grep "Offline_Uncorrectable")
    UDMA_CRC_ERROR_COUNT=$(echo "$SMART_DATA" | grep "UDMA_CRC_Error_Count")

    display_value() {
      attribute=$1
      value=$(echo $attribute | awk '{print $NF}')
      name=$(echo $attribute | awk '{print $2}')
      if [ -z "$value" ] || [ "$value" == "-" ]; then
        printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
      elif [ "$value" -eq "$value" ] 2>/dev/null; then
        if [ "$value" -eq 0 ]; then
          printf "${GREEN}%-25s %15s${NC}\n" "$name" "$value"
        else
          printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
        fi
      else
        printf "${RED}%-25s %15s${NC}\n" "$name" "$value"
      fi
    }

    display_value "$RAW_READ_ERROR_RATE"
    display_value "$REALLOCATED_SECTOR_CT"
    display_value "$SEEK_ERROR_RATE"
    display_value "$SPIN_RETRY_COUNT"
    display_value "$CURRENT_PENDING_SECTOR"
    display_value "$OFFLINE_UNCORRECTABLE"
    display_value "$UDMA_CRC_ERROR_COUNT"

    echo "--------------------------------------"

  fi
  echo
done

NVME_DEVICES=$(nvme list | awk 'NR>2 {print $1}')

for device in $NVME_DEVICES; do
  # smartctl을 사용하여 SMART 정보 가져오기
  SMART_DATA=$(smartctl -a "$device")

  critical_warning=$(echo "$SMART_DATA" | grep "Critical Warning" | awk '{print $3}')
  available_spare=$(echo "$SMART_DATA" | grep -w "Available Spare:" | awk '{print $3}' | sed 's/%//')
  percentage_used=$(echo "$SMART_DATA" | grep "Percentage Used" | awk '{print $3}' | sed 's/%//')
  media_errors=$(echo "$SMART_DATA" | grep "Media and Data Integrity Errors" | awk '{print $6}')
  error_log_entries=$(echo "$SMART_DATA" | grep "Error Information Log Entries" | awk '{print $5}')
  unsafe_shutdowns=$(echo "$SMART_DATA" | grep "Unsafe Shutdowns" | awk '{print $3}')

  display_value() {
    name=$1
    value=$2
    if [ "$name" == "Critical Warning" ]; then
      if [ "$value" == "0x00" ]; then
        printf "${GREEN}%-35s %10s${NC}\n" "$name" "$value"
      else
        printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
      fi
    elif [ "$name" == "Available Spare (%)" ]; then
      if [ "$value" -ge 50 ]; then
        printf "${GREEN}%-35s %10s${NC}\n" "$name" "$value"
      else
        printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
      fi
    elif [ -z "$value" ] || [ "$value" == "-" ]; then
      printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
    elif [ "$value" -eq "$value" ] 2>/dev/null; then
      if [ "$value" -eq 0 ]; then
        printf "${GREEN}%-35s %10s${NC}\n" "$name" "$value"
      else
        printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
      fi
    else
      printf "${RED}%-35s %10s${NC}\n" "$name" "$value"
    fi
  }

  echo -e "${YELLOW}S.M.A.R.T Attribute Values for $device (NVMe):${NC}"
  display_value "Critical Warning" "$critical_warning"
  display_value "Available Spare (%)" "$available_spare"
  display_value "Percentage Used (%)" "$percentage_used"
  display_value "Media and Data Integrity Errors" "$media_errors"
  display_value "Error Information Log Entries" "$error_log_entries"
  display_value "Unsafe Shutdowns" "$unsafe_shutdowns"
  echo "--------------------------------------"
done