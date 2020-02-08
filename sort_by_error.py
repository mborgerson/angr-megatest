#!/usr/bin/env python

import os.path
from tqdm import tqdm
import string
import ast

def main():
    num_files = 0
    for root, dirs, files in os.walk('logs'):
        num_files += len(files)
  
    outfiles = {}

    package_report = open('package_report.txt', 'w')

    t = tqdm(total=num_files, unit='logs')
    for root, dirs, files in os.walk('logs'):
        for f in files:
            with open(os.path.join(root, f), 'r') as f:
                for l in f:
                    if l.startswith('ERROR'):
                        lsplit = l.split()
                        event = lsplit[7][5:-1]

                        def get_field(name):
                            if name in l:
                                return [x for x in lsplit if x.startswith(name)][0].split('=')[1]
                            else:
                                return ''

                        package = get_field('pkg=')
                        elf = get_field('elf=')
                        function = get_field('function=')
                        address = get_field('address=')

                        # Grab the traceback                        
                        l = next(f)
                        tb = []
                        if l.startswith('Traceback'):
                            tb.append(l)
                            while True:
                                l = next(f)
                                tb.append(l)
                                if not l.startswith('  '):
                                    break

                        r = '#'*80 + '\n'
                        r += '### EVENT: ' + event + '\n'
                        r += '### Package: ' + package + '\n'
                        r += '### Binary: ' + elf + '\n'
                        r += '### Function: ' + function + '\n'
                        r += '### Execption:\n'
                        r += ''.join(tb) + '\n'
                        r += '\n\n'

                        cat = event + '-' + (tb[-1].split()[0].strip(':') if len(tb)>0 else 'OTHER')
                        if cat not in outfiles:
                            outfiles[cat] = open(os.path.join('output', cat), 'w')
                        outfiles[cat].write(r)
                    elif l.startswith('INFO') and ('RESULTS:' in l):
                        lsplit = l.split()
                        event = lsplit[7][5:-1]

                        def get_field(name):
                            if name in l:
                                return [x for x in lsplit if x.startswith(name)][0].split('=')[1]
                            else:
                                return ''

                        package = get_field('pkg=')
                        elf = get_field('elf=')
                        reasons = ast.literal_eval(l[:-5].split('reasons=')[-1])
                        package_report.write('%s | %s | %s\n' % (
                            package,
                            elf,
                            str(reasons)))
            t.update()
    t.close()

    for c in outfiles:
        outfiles[c].close()
    package_report.close()

if __name__ == '__main__':
    main()
