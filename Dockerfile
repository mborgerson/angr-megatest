from angr/angr:latest

user angr
workdir /home/angr
run /home/angr/.virtualenvs/angr/bin/pip install stopit
copy process_package.sh /home/angr
copy analyze_binary.py /home/angr
