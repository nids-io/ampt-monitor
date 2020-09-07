# ampt-monitor-zeek
Module to read healthcheck signature notices from Zeek logs for the AMPT
monitor.

See [AMPT][ampt] for more information on the AMPT framework and the problems
it solves.

**ampt-monitor-zeek** is a module for ampt-monitor, the healthcheck event
reporting component in the AMPT framework. It monitors Zeek signature logs to
extract alert data for healthcheck probes and passes the data to ampt-monitor
for delivery to the AMPT manager.

## Installation and usage
See the [Wiki][wiki] for further documentation.


[ampt]: https://github.com/nids-io/ampt-manager/wiki/AMPT
[wiki]: https://github.com/nids-io/ampt-monitor/wiki/
