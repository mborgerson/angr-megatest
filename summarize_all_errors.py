#!/usr/bin/env python
"""
Parses .summary files to join their results and update the csv file
"""
import os
import os.path
import re

class ErrorCategory:
	def __init__(self, name):
		self.name = name
		self.variants = []
		self.breakdown = ''
	def add_variant(self, count, entry):
		self.variants.append((count, entry))
	@property
	def total_number_of_errors(self):
		return sum(map(lambda x: x[0], self.variants))
	@property
	def errors(self):
		return sorted(self.variants, key=lambda x: x[0], reverse=True)

class Analyis:
	# Collection of Error categories for a given run
	def __init__(self, date):
		self.date = date
		self.errors = {}
	def add_error_category(self, err):
		self.errors[err.name] = err

analysis = Analyis(202001310000)

def parse_summary_file(path):
	'''Grab the summary contents listing (Count' 'Exception)'''
	err = ErrorCategory(path[0:-8]) # Strip off .summary
	f = open(path)
	for i,l in enumerate(f.readlines()):
		if i < 4: continue
		l = l.strip()
		if l == '': continue
		if l.startswith('Sample'): break
		m = re.match('^(\d+) (.+)', l)
		err.add_variant(int(m.group(1)), m.group(2))
	f.seek(0)
	breakdown = f.read()
	err.breakdown = breakdown
	analysis.add_error_category(err)

for (root, dirs, files) in os.walk('.'):
	for f in files:
		if f.endswith('.summary'):
			parse_summary_file(f)

# Dump this analysis summary to a file
with open(str(analysis.date), 'w') as f:
	f.write('Analysis Errors\n')
	f.write(('=' * 80) + '\n')
	for k in sorted(analysis.errors, key=lambda k:analysis.errors[k].total_number_of_errors, reverse=True):
		e = analysis.errors[k]
		f.write('%8d %s' % (e.total_number_of_errors, e.name))
		f.write('\n')
	f.write('\n')

	for k in sorted(analysis.errors, key=lambda k:analysis.errors[k].total_number_of_errors, reverse=True):
		e = analysis.errors[k]
		f.write('Error Summary: ' + e.name + '\n')
		f.write(('-' * 80) + '\n')
		f.write(e.breakdown)
		f.write('\n')

analyses = [analysis]
analyses.sort(key=lambda x: x.date)
all_errors_ever = []
for a in analyses:
	for k in a.errors:
		if k not in all_errors_ever:
			all_errors_ever.append(k)
all_errors_ever.sort()

# FIXME: Import existing CSV, build analysis objects and combine with currrent
# analysis to gen new stats.csv

import csv
with open('stats.csv', 'w') as csvfile:
	writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
	writer.writerow(['Error'] + map(lambda x: x.date, analyses))
	for error in all_errors_ever:
		row = [error]
		for a in analyses:
			# Check to see if this error appeared in this analysis
			if error in a.errors:
				count = a.errors[error].total_number_of_errors
			else:
				count = 0
			row.append(count)
		writer.writerow(row)
