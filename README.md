# ampt-monitor

Sensor alert monitor for the AMPT passive network tools monitor 

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

ampt-monitor is intended to be modular in design. The core monitor provides
basic runtime functionality, communication with the AMPT manager, and
configuration handling. Decoupled modules function as plugins capable of
reading alert logs or related data for a given sensor technology to extract
AMPT healthcheck probe alerts. Currently a basic module for the Suricata
EVE format is provided, and other log formats are planned for future
development.

Other AMPT components include:

* [ampt-manager][ampt_manager] - Management service for the AMPT passive
  network tools monitor
* [ampt-generator][ampt_generator] - Healthcheck packet generator for the
  AMPT passive network tools monitor

## Installation and usage

See the [Wiki][wiki] for further documentation.


[suricata]: https://suricata-ids.org/
[snort]: https://www.snort.org/
[bro]: https://www.bro.org/
[moloch]: https://github.com/aol/moloch
[ampt_manager]: https://github.com/nids-io/ampt-manager
[ampt_generator]: https://github.com/nids-io/ampt-generator
[ampt_monitor]: https://github.com/nids-io/ampt-monitor
[ampt]: https://github.com/nids-io/ampt-manager/wiki/AMPT
[wiki]: https://github.com/nids-io/ampt-monitor/wiki/

