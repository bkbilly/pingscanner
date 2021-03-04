#!/usr/bin/env python3

""" Import Python library """
import sys
import platform
import ipaddress
import asyncio
import re
from mac_vendor_lookup import AsyncMacLookup
import socket


class Networkscan:
    """Class Networkscan"""

    def __init__(self, ip_and_prefix):
        """Class init"""

        self.list_of_hosts_found = []
        self.my_list_of_tasks = []
        self.my_tasks = []
        self.system = platform.system().lower()

        try:
            # Use ipaddress library
            self.network = ipaddress.ip_network(ip_and_prefix)
        except:
            # Problem with input network
            sys.exit("Incorrect network/prefix " + ip_and_prefix)

        # Calculate the number of hosts
        self.nbr_host = self.network.num_addresses

        # Network and mask address to remove? (no need if /31)
        if self.network.num_addresses > 2:
            self.nbr_host -= 2

    async def ping_coroutine(self, ip, checkmac, checkvendor):
        """ Async procedure

        ping_coroutine is the coroutine used to send a ping
        """

        # Define the ping command used for one ping (Windows and Linux versions are different)
        if self.system == "windows":
            one_ping_param = "ping -n 4 -l 1 -w 1000 "
        else:
            one_ping_param = "ping -c 4 -s 1 -w 1 "

        # Run the ping shell command
        # stderr is needed in order not to display "Do you want to ping broadcast? Then -b. If not,
        # check your local firewall rules." on Linux systems
        running_coroutine = await asyncio.create_subprocess_shell(
            one_ping_param + ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        # Suspends the current coroutine allowing other tasks to run
        stdout_ping = await running_coroutine.communicate()

        # Ping OK?
        if "ttl=" in str(stdout_ping).lower():
            # Ping OK
            mac, hostname = None, None
            vendor = None
            if checkmac:
                mac, hostname = await self.mac_coroutine(ip)
                if mac is not None:
                    if checkvendor:
                        vendor = await AsyncMacLookup().lookup(mac)
                    self.list_of_hosts_found.append({
                        'ip': ip,
                        'mac': mac,
                        'vendor': vendor,
                        'hostname': hostname
                    })
            else:
                self.list_of_hosts_found.append({'ip': ip})

    async def mac_coroutine(self, ip):
        running_arp_coroutine = await asyncio.create_subprocess_shell(
            f"arp -a {ip}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)

        # Suspends the current coroutine allowing other tasks to run
        stdout_arp = await running_arp_coroutine.communicate()
        arp_out = str(stdout_arp[0].decode('ascii'))
        p = re.compile(r' (?:[0-9a-fA-F][:-]?){12}')
        found_mac = re.findall(p, arp_out)

        mac = None
        hostname = None
        if len(found_mac) > 0:
            mac = found_mac[0].replace('-', ':').upper().strip()
            hostname = await self.hostname_coroutine(ip, arp_out)

        return mac, hostname

    async def hostname_coroutine(self, ip, arp_out):
        if self.system == "windows":
            hostname = socket.getfqdn(ip)
        else:
            p = re.compile(r'^[\w-]+')
            find_hostname = re.findall(p, arp_out)
            if len(find_hostname) > 0:
                hostname = find_hostname[0]
        return hostname

    async def run_coroutins(self):
        """ Async procedure

        run_coroutins run the list of coroutines, list by list
        """

        # Start the tasks
        # Wait until both tasks are completed
        # Run all commands

        # Read the lists one by one from the list of lists my_list_of_tasks
        for each_task_list in self.my_list_of_tasks:
            # Start the coroutines one by one from the current list
            for each_coroutine in asyncio.as_completed(each_task_list):
                await each_coroutine

    def run(self, mac=True, vendor=False):
        """ Method used to create the task lists and to run the coroutine loop """

        # By default at the beginning of every scan there is no host found
        self.list_of_hosts_found = []
        self.my_tasks = []

        # The list of list my_list_of_tasks groups lists of coroutines
        self.my_list_of_tasks = []
        # By default the current list is added to the list of list my_list_of_tasks
        # A very important concept is that filling the empty list my_tasks will
        # also fill the current list of lists my_list_of_tasks.
        self.my_list_of_tasks.append(self.my_tasks)

        hosts = list(self.network.hosts())
        if self.network.num_addresses == 1:
            hosts = [self.network.network_address]

        # Create the coroutines tasks
        for host in hosts:
            # my_tasks is a list with coroutine tasks. It gets 2 parameters: one with
            #  the ping command and the other one with the ip address of the target
            self.my_tasks.append(self.ping_coroutine(str(host), mac, vendor))

        # if Windows is in use then these commands are needed otherwise
        # "asyncio.create_subprocess_shell" will fail
        if self.system == "windows":
            asyncio.set_event_loop_policy(
                asyncio.WindowsProactorEventLoopPolicy())

        # Run the coroutine loop
        asyncio.run(self.run_coroutins())



# Main function
if __name__ == '__main__':
    # Create the object
    my_scan = Networkscan("192.168.2.0/24")

    # Display information
    print("Network to scan: " + str(my_scan.network))
    print("Prefix to scan: " + str(my_scan.network.prefixlen))
    print("Number of hosts to scan: " + str(my_scan.nbr_host))

    # Run the network scan
    print("Scanning hosts...")

    # Run the scan of hosts using pings
    my_scan.run(mac=True, vendor=True)

    # Display the IP address of all the hosts found
    for i in my_scan.list_of_hosts_found:
        print(i)
    print("Number of hosts found: " + str(len(my_scan.list_of_hosts_found)))
