# ampt-monitor-suricata

Module to read healthcheck alerts from Suricata EVE logs for the AMPT monitor

See [AMPT][ampt] for more information on the AMPT framework and the problems
it solves.

**ampt-monitor-suricata** is a module for ampt-monitor, the healthcheck event reporting component in the AMPT framework. It monitors Suricata EVE logs to extract alert data for healthcheck probes and passes the data to ampt-monitor for delivery to the AMPT manager.

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

