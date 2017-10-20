# Suricata development setup

When testing with Suricata and the AMPT suite, various configurations work
fine. This is a simple setup that works fine on a testing environment using
macOS and Suricata 4.0.0 RELEASE.

1. Using Homebrew, install *suricata*. Homebrew typically has a recent
   Suricata build. It is mostly rooted (config, etc.) in
   `/usr/local/etc/suricata`.
2. The default build of the suricata formula doesn't include libjanssen so you
   need to modify the build options:

        $ brew install suricata --with-jansson

   After the build completes, Suricata should have the necessary support for
   logging in EVE format. This can be verified by looking at the build info:

        $ /usr/local/bin/suricata --build-info

3. Install a development configuration file for Suricata that provides minimal
   changes to defaults and includes a `local.rules` file for inclusion of the
   healthcheck rule from the AMPT Generator. The sample configuration file in
   this repository may be installed in this path:

        /usr/local/etc/suricata/suricata_dev.yaml

4. Start Suricata and listen on the loopback interface. This supports an AMPT
   configuration where a monitored segment targets a port on the address
   127.0.0.1 and a local AMPT Generator is configured and running.

        $ sudo suricata -c /usr/local/etc/suricata/suricata_dev.yaml -i lo0

5. The AMPT Monitor configuration (default: `/etc/ampt-monitor.conf`) may then
   be set to configure the `suricata_eve` plugin to point to the default EVE
   log file path:

        [monitors]
        
        [[suricata_eve]]
        monitor_id = 1
        rule_id = 3900001
        path = /usr/local/var/log/suricata/eve.json


