#!/usr/bin/env python
"""
Policy Auto Sign for Puppet

Dependencies :
    python-netaddr
    python-mysql
    python-ldap
    python-redis

Description :

This script will be called every time when puppet master receives a certificate signing request (CSR). 
The new CSR will be signed only if this script exists successfully with exist code = 0. The only argu-
ment accepted is the certname, which is usually the FQDN of the client server. However, in our deploy-
ment, certname has been explictly set to client's IP address by setting certname = IP in puppet.conf.

Author : Lei Zhang


"""
#Import modules.
import sys
import os
import socket
import ldap
import redis
import ConfigParser
import logging
import MySQLdb as mdb
from netaddr import IPNetwork, IPAddress


#Set global variables 

#Read parameters and configuration file
cert_name = sys.argv[1] #The first parameter of the script is the cert_name, the client's IP address.
conf_file = os.path.dirname(os.path.realpath(__file__)) + '/conf/config.ini' # Configure file path
config = ConfigParser.ConfigParser()
config.read(conf_file)

#Read instances' IP range of SA from the configuration file
sa_instance_network = config.get('global','sa_instance_network')

#Set log file name and format
log_dir = os.path.dirname(os.path.realpath(__file__)) + '/log/'
log_file = log_dir + os.path.splitext(os.path.basename(__file__))[0] + ".log"
if not os.path.exists(log_dir): #Create the log dir
    os.mkdir(log_dir)
logging.basicConfig(filename=log_file,
                    level=logging.INFO,
                    format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p')

def is_valid_ip(addr):
    #Test if an IP address is valid
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False


def is_sa_ip(addr):
    #Test if an IP address is within SA's IP range
    if IPAddress(addr) in IPNetwork(sa_instance_network):
        return True
    else:
        return False

def get_tenant_by_ip(addr):
    #Get tenant ID by IP address

    #Set Mysql connection parameters.
    host = config.get('mysql','host')
    user = config.get('mysql','user')
    password = config.get('mysql','password')
    database = config.get('mysql','database')

    try:
        con = mdb.connect(host, user, password, database);
        cur = con.cursor()
        cur.execute("select address,instance_uuid,project_id,user_id from fixed_ips \
                    join instances on fixed_ips.address='"+addr+"' \
                    and fixed_ips.instance_uuid=instances.uuid and instances.deleted=0");
        result = cur.fetchall()
        con.close()
        if len(result) == 0:
          return False
        instance_uuid = result[0][1]
        return (result[0][1],result[0][2]) #Return instance_uuid and tenant_id
    except mdb.Error, e:
        print ("MYSQL-ERROR %d: %s" % (e.args[0],e.args[1]))
        logging.info("MYSQL-ERROR %d: %s" % (e.args[0],e.args[1]))
        sys.exit(1)


def is_authorized_tenant(tenant_id):
    #Test if the tenant is our user
    
    #Set LDAP connection parameters
    url = config.get('ldap','url')
    binddn = config.get('ldap','binddn')
    bindpw = config.get('ldap','bindpw')
    basedn = config.get('ldap','basedn')

    ld  = ldap.initialize(url)
    ld.simple_bind_s(binddn,bindpw)
    filter = "(ou="+tenant_id+")"   #Filter by tenant_id
    attr = ['ou']
    results = ld.search_s(basedn,ldap.SCOPE_SUBTREE,filter,attr)
    if len(results) == 0:
        return False
    else:
        return True


def update_instance_status(uuid,ip):
    #Update instance in Redis

    #Set Redis connection parameters
    host = config.get('redis','host')
    port = int(config.get('redis','port'))
    r = redis.StrictRedis(host, port, db=0)
    return r.setnx(uuid,ip) #Set key(uuid)=value(ip) in Redis if key does not exist

def set_hiera(tenant_id,ip):
    #Generate a host-specific yaml file for the client

    dynamic_hiera_dir = config.get('global','dynamic_hiera_dir')
    host_yaml = dynamic_hiera_dir + ip + ".yaml"
    fp = open(host_yaml,'w')
    fp.write("ersa_nss_ldap::tenant_id : " + tenant_id + "\n") #Set ersa_nss_ldap::tenant_id in hiera for the client
    fp.close()

    #It is not nice, but always return true here
    return True


def main():
    #Main
    
    #Test if the IP is a valid IP
    if not is_valid_ip(cert_name):
        print ("REJECTED : %s is not a legal IP address." % cert_name )
        logging.info("REJECTED : %s is not a legal IP address." % cert_name )
        sys.exit(1)
   
    #Test if the IP address is within SA's IP range
    if not is_sa_ip(cert_name):
        print ("REJECTED : %s is not a SA IP address." % cert_name )
        logging.info("REJECTED : %s is not a SA IP address." % cert_name )
        sys.exit(1)
 
    #Get tenant info by IP address
    tenant_info = get_tenant_by_ip(cert_name)
    if not tenant_info:
        print ("REJECTED : %s has no tenant in the database." % cert_name )
        logging.info("REJECTED : %s has no tenant in the database." % cert_name )
        sys.exit(1)
 
    (uuid,tenant) = tenant_info
   
   
    #Test if the tenant is our user
    if is_authorized_tenant(tenant):
        if update_instance_status(uuid,cert_name):
            #Generate host-specific yaml file for the client
            set_hiera(tenant,cert_name)
            print ("REDIS-UPDATE : set %s = %s in Redis successfully." % (uuid,cert_name))
            logging.info("REDIS-UPDATE : set %s = %s in Redis successfully." % (uuid,cert_name))
            print ("APPROVED : %s is an instance of SA local tenant %s." % (cert_name,tenant))
            logging.info("APPROVED : %s is an instance of SA local tenant %s." % (cert_name,tenant))
            sys.exit(0)
        else:
            print ("REDIS-UPDATE : conflict key %s found in Redis." % uuid)
            logging.info("REDIS-UPDATE : conflict key %s found in Redis." % uuid)
            print ("REJECTED : failed to set %s = %s in Redis." % (uuid,cert_name))
            logging.info("REJECTED : failed to set %s = %s in Redis." % (uuid,cert_name))
            sys.exit(1)
    else:
        print ("REJECTED : %s is not a SA local tenant" % tenant)
        logging.info("REJECTED : %s is not a SA local tenant" % tenant)
        sys.exit(1)

if __name__ == "__main__":
    main()
