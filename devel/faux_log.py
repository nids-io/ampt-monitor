#!/usr//bin/env python3
#
# Helper script to append various types of log entries to a sample monitored
# file for testing of file reader input plugins. Sample log entries have
# dynamic timestamps but are otherwise static as defined in the alert_type
# dictionary. The timestamp format emitted is the 2.1 format as shown below.
#
# Timestamp format Suricata 2.1: 2017-10-05T14:28:21.979637
# Timestamp format Suricata 4.0: 2017-10-09T13:52:17.962402-0700

import sys
import time
import argparse
from datetime import datetime


alert_type = {
    'real': [
        '{"timestamp":"%s","flow_id":140568631225664,"event_type":"alert","src_ip":"127.0.0.1","src_port":51850,"dest_ip":"10.0.1.1","dest_port":5471,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":3900001,"rev":1,"signature":"NIDS HEALTH MONITORING","category":"Not Suspicious Traffic","severity":3,"tx_id":0}}',
    ],
    'fake': [
        '{"timestamp":"%s","flow_id":140568631382541,"event_type":"alert","src_ip":"74.221.209.160","src_port":31128,"dest_ip":"10.8.6.136","dest_port":44934,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000031,"rev":4,"signature":"LOCAL CURRENT_EVENTS Sutra TDS Structured Format Cookie Response","category":"Misc Attack","severity":2,"tx_id":0}}',
        '{"timestamp":"%s","flow_id":140568624856410,"event_type":"alert","src_ip":"91.88.109.120","src_port":4197,"dest_ip":"10.0.0.146","dest_port":18537,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":1000031,"rev":4,"signature":"LOCAL CURRENT_EVENTS Sutra TDS Structured Format Cookie Response","category":"Misc Attack","severity":2,"tx_id":0}}',
        '{"timestamp":"%s","flow_id":140530902507472,"event_type":"alert","src_ip":"10.8.7.105","src_port":59592,"dest_ip":"165.227.12.12","dest_port":31128,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2815475,"rev":5,"signature":"ETPRO CURRENT_EVENTS Possible Nuclear EK Landing URI struct Dec 27 2015 M1","category":"A Network Trojan was detected","severity":1,"tx_id":0}}',
    ],
    'junk': [
        '%s Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.',
        '%s Information about the types of higher education institutions that grant degrees in Biophysics and the types of students that study this field. Brigham Young University-Provo awards the most degrees in graphic design in the US, but Centenary College of Louisiana and La Sierra University have the highest percentage of degrees awarded in Biophysics. Tuition costs for Biophysics majors are, on average, $11,220 for in-state public colleges, and $3900001 for out of state private colleges. The largest share of institutions with Biophysics programs are Private not-for-profit, 4-year or above institutions.',
        '%s I will be visiting the UK next week! You can join me in London from September 30-October 2 (at New Scientist Live, The Royal Institution, and Intelligence Squared), then from October 3-6 in York, Edinburgh, Cambridge and Ely, Oxford, and Cheltenham.',
        '%s Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et dolore magnam aliquam quaerat voluptatem. Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?',
        '%s At vero eos et accusamus et iusto odio dignissimos ducimus qui blanditiis praesentium voluptatum deleniti atque corrupti quos dolores et quas molestias excepturi sint occaecati cupiditate non provident, similique sunt in culpa qui officia deserunt mollitia animi, id est laborum et dolorum fuga. Et harum quidem rerum facilis est et expedita distinctio. Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus, omnis voluptas assumenda est, omnis dolor repellendus. Temporibus autem quibusdam et aut officiis debitis aut rerum necessitatibus saepe eveniet ut et voluptates repudiandae sint et molestiae non recusandae. Itaque earum rerum hic tenetur a sapiente delectus, ut aut reiciendis voluptatibus maiores alias consequatur aut perferendis doloribus asperiores repellat.',
    ],
}

def get_ts():
    return datetime.now().isoformat()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=argparse.FileType('a'),
                        help='file to write log to')
    parser.add_argument('-t', '--type', choices=alert_type.keys(),
                        default='real',
                        help=('type of log to write to file '
                              '(default: %(default)s)'))
    args = parser.parse_args()

    for alert in alert_type[args.type]:
        args.file.write(alert % get_ts() + '\n')
        time.sleep(0.5)

if __name__ == '__main__':
    main()
