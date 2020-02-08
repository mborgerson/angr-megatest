import sys
print('Summary')
print('=====================================')
records = []
currentRecord = None
f = open(sys.argv[1])
for line in f:
	line = line.strip()
	if line == '':
		continue
	if line.startswith(u'################################################################################'):
		# Start of new record
		if currentRecord is not None:
			records.append(currentRecord)
		currentRecord = []
		continue
	else:
		currentRecord.append(line)
if currentRecord is not None:
	records.append(currentRecord)

lines = {}
samples = {}
for r in records:
	last_line = r[-1]
	if last_line not in lines:
		lines[last_line] = 0
		samples[last_line] = r
	lines[last_line] += 1
print('Num records: %d\n' % len(records))
for err in sorted(lines, key=lambda x: lines[x], reverse=True):
	print('%8d %s' % (lines[err], err))

for err in sorted(lines, key=lambda x: lines[x], reverse=True):
	print('')
	print('')
	print('Sample of %s (%d occurences): ' % (err, lines[err]))
	print('    ' + '\n    '.join(samples[err]))
