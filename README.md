angr megatest
=============
Tools for large-scale program analysis over the Debian stretch package set,
spanning many architectures.

**WARNING:** Understand that you will be spinning up over 100k containers
to do this analysis. This can incur significant cost. Consider limiting your
testing to check for stability/usage statistics before burning through your 
cloud budget.

Regenerating list of packages
-----------------------------
The list of packages that are tested come straight from the Debian repositories.
To regenerate the list of packages, build the docker image from
`list.dockerfile`, then run the `generate_package_list.sh` script.
You will need the program `fromdos` installed, available in the `tofrodos`
package.

```bash
sudo apt install tofrodos
docker build -t binster -f list.dockerfile .
./generate_package_list.sh > list
```

Each line should look like:
```
./process_package.sh s/sssd/sssd-dbus-dbgsym_1.15.0-3+deb9u1_ppc64el.deb #sssd-dbus-ppc64el.deb
```

Running the experiment
----------------------
The `list` file contains invocations of the `process_package.sh` script for the set of
packages.

The `process_package.sh` script does the processing for a single package. It will
download the package and corresponding debug symbols package from the Debian
repository, extract the packages, discover any executable files, then attempt to
do an analysis via `analyze_binary.py` on each executable.

`analyze_binary.py` will attempt to load the executable, construct the CFG, enumerate
all symbols, and attempt to decompile each symbol. Crashes and timeouts are
captured and logged.

megatest is designed to be containerized and run on a large-scale Kubernetes
cluster. To build the container:

```
docker build -t yourname/megatest .
```

Now you can run a single experiment locally with:

```
docker run yourname/megatest ./process_package.sh s/sssd/sssd-dbus-dbgsym_1.15.0-3+deb9u1_ppc64el.deb
```

You can perform large-scale distributed analysis by submitting jobs from the list file. [kuboid](https://github.com/zardus/kuboid) is good for this purpose.

First make sure you have pushed your container to DockerHub:

```
docker push yourname/megatest
```

Then you can then run the experiment with:

```
monitor_experiment -f list -l logs -i yourname/megatest
```

As jobs complete, the `logs` directory will be populated with a log file for
each package analyzed. 

Post-processing
---------------
FIXME
