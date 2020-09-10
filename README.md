# ampt-monitor

Sensor alert reader for the AMPT passive network tools monitor.

AMPT is a practical framework designed to aid those who operate network IDS
sensors and similar passive security monitoring systems. A tailored approach
is needed to actively monitor the health and functionality of devices that
provide a service based on capturing and inspecting network traffic. AMPT
supports these types of systems by allowing operators to validate traffic
visibility and event logging on monitored network segments. Examples of
systems that can benefit from this type of monitoring are:

* [Suricata IDS][suricata]
* [Snort IDS][snort]
* [Bro IDS][bro]
* [Moloch][moloch]

See [AMPT][ampt] for more information on the AMPT framework and the problems
it solves.

**ampt-monitor** functions as a healthcheck event reporting component in the
AMPT framework. It runs on network sensors or other hosts that have access to
event logs for monitored network segments and reports healthcheck alerts to
the AMPT manager. It is implemented in Python and is simple to deploy.

## Plugins
ampt-monitor is modular. The core monitor provides basic runtime
functionality, communication with the AMPT manager, and configuration
handling. Plugins read alert logs or related data for a given sensor
technology to extract AMPT healthcheck probe alerts.

ampt-monitor plugins can be found in the nids.io repositories under the
[ampt-monitor-plugin][ampt_monitor_plugin] topic.

Currently available plugins from the nids-io project:

* [ampt-monitor-suricata][ampt_monitor_suricata]
* [ampt-monitor-zeek][ampt_monitor_zeek]

## Installation and usage
This repository carries the `ampt-monitor` core. This package as well as one
or more monitor plugins should be installed.

See the [Wiki][wiki] for further documentation.

Other AMPT components include:

* [ampt-manager][ampt_manager] - Management service for the AMPT passive
  network tools monitor
* [ampt-generator][ampt_generator] - Healthcheck packet generator for the
  AMPT passive network tools monitor

[suricata]: https://suricata-ids.org/
[snort]: https://www.snort.org/
[bro]: https://www.bro.org/
[moloch]: https://github.com/aol/moloch
[ampt_manager]: https://github.com/nids-io/ampt-manager
[ampt_generator]: https://github.com/nids-io/ampt-generator
[ampt_monitor]: https://github.com/nids-io/ampt-monitor
[ampt]: https://github.com/nids-io/ampt-manager/wiki/AMPT
[wiki]: https://github.com/nids-io/ampt-monitor/wiki/
[ampt_monitor_plugin]: https://github.com/search?q=org%3Anids-io+topic%3Aampt-monitor-plugin&type=Repositories
[ampt_monitor_suricata]: https://github.com/nids-io/ampt-monitor-suricata
[ampt_monitor_zeek]: https://github.com/nids-io/ampt-monitor-zeek
