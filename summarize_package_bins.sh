#!/bin/bash
# Determine how many packages were tested and which binaries could even start
# analysis
echo $(wc -l list | cut -f1 -d' ') original packages in list
echo $(ls -l logs | cut -f5 -d' ' | grep 111 | wc -l) failed log downloads
echo $(cat package_report.txt | cut -f1 -d '|' | uniq | wc -l) packages tested
echo $(cat package_report.txt | cut -f2 -d '|' | uniq | wc -l) binaries tested
echo $(grep ELF_OPEN_FAIL package_report.txt | wc -l) failed elf opens
echo $(grep DBG_OPEN_FAIL package_report.txt | wc -l) failed dbg opens
echo $(grep CFG_FAIL package_report.txt | wc -l) failed cfg
echo $(grep CFG_SUCCESS package_report.txt | wc -l) success cfg
