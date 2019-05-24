# OTRS-ShibAuth

With the help of this OTRS module, we can log in to OTRS users identified through Shibboleth. If the user profile does not exist yet, it automatically creates and provides the appropriate privileges.

The module has been tested in the following software environment:
OTRS 6.0.17, Debian 9, Apache 2.4.25, shibboleth-sp2 2.6.0, libapache2-mod-shib2 2.6.0

# Installation and setup guide

0. Perform the OTRS (https://doc.otrs.com/doc/manual/admin/6.0/en/html/installation.html ) and the Shibboleth SP (https://wiki.niif.hu/index.php?title=Shibboleth_Service_Provider_(SP) ) installation and default configuration. 
1. Prepare the Shibboleth attribute map based on the etc/shibboleth/attribute-map.xml file. Ensure that you have the permission for SP to query these attributes (SP must specify these attributes)
2. If you want to assign your agents to roles based on an external attribute source (eg, hexaa), you should also register the service with hexaa or make the following change:https://wiki.niif.hu/index.php?title=Shibboleth_Service_Provider_(SP)#HEXAA_integr.C3.A1ci.C3.B3
3. Files from the opt/otrs/Kernel/System folder move to your OTRS installation directory and edit the Config.pm file according to the given pattern
4. In Apache config, you can specify that only those agents with the required attributes have access to the administrative interface, furthermore to the customer interface can access everybody:

```
<Location /otrs>
    AuthType shibboleth
    ShibRequestSetting requireSession 1
    <RequireAny>
        Require shib-attr entitlement ~ "^urn:geant:yourdomain\.tld:AA:X:([^;]*)$"
        Require shib-attr scoped-affiliation = "employee@yourdomain.tld"
    </RequireAny>
    ShibUseHeaders On
</Location>

<Location /otrs/customer.pl>
    Require all granted
</Location>

```

If the modules are not working properly, you can get a more detailed output in the log file by setting the "$ Self -> {Debug}" variable in the module, which can help to detect and troubleshoot the problem.
