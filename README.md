# remove_miner_fees

Removes miner fees using nfqueue. Tested on ubuntu 16.04 mining on nanopool with claymore dual ethereum miner for linux version 9.4.

# How does this work?

It modifies outgoing packets using nfqueue, substituting the dev fee wallet address with your own wallet address.

# Setup

Disable ufw

```
sudo ufw disable
```

Install python-nfqueue

```
sudo apt-get install python-nfqueue
```

Download the program and run it as root (nfqueue needs to be run as root). Keep it running in the background

```
wget https://raw.githubusercontent.com/gkovacs/remove_miner_fees/master/remove_mining_fees.py
sudo python remove_miner_fees.py
```

Now you can start the miner

```
./ethdcrminer64 -epool eth-us-west1.nanopool.org:9999 -ewal 0xb70fc6f9865ce18c20d90ebf067d9951918f8933/someworker -epsw x -dpool stratum+tcp://siamining.com:7777 -dwal 74ab711929bfc28359c8485a4e488d2f89b623771788fbeca7e7f5fe993ec691fec713e9f35b.someworker -dcoin sia -dcri 70
```

Logging output, with modified packets, will be written to a file named `remove_mining_fees_log.txt`

# Specifying where mining fees should be redirected

Note that this program redirects mining fees to `0xb70fc6f9865ce18c20d90ebf067d9951918f8933` by default. You will want to substitute that with your own wallet address in the source code by editing the variable `my_eth_address`

# Using pools other than nanopool

Note that this program assumes port `9999` by default (used by nanopool). Substitute the port by editing the number after `--dport 9999` in the `iptables` command.

# Using miners other than Claymore

If you are using a miner different than claymore ethereum, you will need to figure out what the dev fee addresses are for that miner so you can redirect them - you can do so by running `tcpdump -i enp4s0 host eth-us-west1.nanopool.org -X > log_mining_activity.txt` then looking through `log_mining_activity.txt` for strings that look like `eth_submitLogin`. Find the addresses, and add them to list `addresses_to_redirect`

# Author

[Geza Kovacs](https://github.com/gkovacs/)

# Donations

ETH `0xb70fc6f9865ce18c20d90ebf067d9951918f8933`

BTC `1PYmDbxXDS9FjAdH8jxE2stdf1Yrsvqdos`

ZEC `t1Yi9izeKkWbVtXRrQNdUbs7BdZVbwVVRcw`

SIA `74ab711929bfc28359c8485a4e488d2f89b623771788fbeca7e7f5fe993ec691fec713e9f35b`
