#!/bin/bash
echo "Memory Module Serial Numbers:"
dmidecode -t memory | grep -A10 'Locator: ' | grep Serial.Number | grep -v NO.DIMM

module_count=$(dmidecode -t memory | grep -A10 'Locator: ' | grep Serial.Number | grep -v NO.DIMM | wc -l)
echo "Total Memory Modules: $module_count"

echo "Memory Error Count Files:"
ls -l /sys/devices/system/edac/mc/mc*/csrow*/*ce_count

echo "Memory Correctable Error (CE) Counts:"
grep "[0-9]" /sys/devices/system/edac/mc/mc*/csrow*/*_ce_count

echo "Memory Error Check Completed."