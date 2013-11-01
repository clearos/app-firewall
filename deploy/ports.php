<?php

/**
 * Firewall ports list.
 *
 * The port list below describes all we need to now about a particular
 * service/port:
 * - the type (normal/special... see next note)
 * - the protocol
 * - the port (TCP/UDP protocols only care about this)
 * - a human readable name
 *
 * A user expects to see thins like 'allow PPTP connections' in the default 
 * list of services.  They don't care that we have to do things differently
 * in the firewall.  The firewall class will handle thies special cases.
 *
 * @category   apps
 * @package    firewall
 * @subpackage configuration
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2006-2011 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/firewall/
 */

$ports = array();
$ports[] = array('normal',  'TCP', '20',    'FTP');
$ports[] = array('normal',  'TCP', '21',    'FTP');
$ports[] = array('normal',  'TCP', '22',    'SSH');
$ports[] = array('normal',  'TCP', '25',    'SMTP');
$ports[] = array('normal',  'TCP', '80',    'HTTP');
$ports[] = array('normal',  'TCP', '81',    'Webconfig');
$ports[] = array('normal',  'TCP', '83',    'Webmail');
$ports[] = array('normal',  'TCP', '110',   'POP3');
$ports[] = array('normal',  'TCP', '113',   'Ident');
$ports[] = array('normal',  'UDP', '123',   'NTP');
$ports[] = array('normal',  'TCP', '139',   'SMB');
$ports[] = array('normal',  'TCP', '143',   'IMAP');
$ports[] = array('normal',  'TCP', '389',   'LDAP');
$ports[] = array('normal',  'TCP', '443',   'HTTPS');
$ports[] = array('normal',  'TCP', '445',   'SMB over TCP');
$ports[] = array('normal',  'TCP', '636',   'LDAPS');
$ports[] = array('normal',  'TCP', '873',   'Rsync');
$ports[] = array('normal',  'TCP', '989',   'FTPS');
$ports[] = array('normal',  'TCP', '990',   'FTPS');
$ports[] = array('normal',  'TCP', '993',   'IMAPS');
$ports[] = array('normal',  'TCP', '995',   'POP3S');
$ports[] = array('normal',  'TCP', '1080',  'Proxy/SOCKS');
$ports[] = array('normal',  'UDP', '1194',  'OpenVPN');
$ports[] = array('normal',  'TCP', '1194',  'OpenVPN TCP');
$ports[] = array('normal',  'TCP', '1214',  'KaZaa/Morpheus');
$ports[] = array('normal',  'TCP', '1863',  'MSN');
$ports[] = array('normal',  'TCP', '1875',  'ClearSDN');
$ports[] = array('normal',  'TCP', '2121',  'FTP Homes');
$ports[] = array('normal',  'UDP', '4569',  'IAX2');
$ports[] = array('normal',  'TCP', '5190',  'ICQ/AIM');
$ports[] = array('normal',  'TCP', '6346',  'Gnutella');
$ports[] = array('normal',  'TCP', '6588',  'Proxy/AnalogX');
$ports[] = array('normal',  'TCP', '6667',  'IRC');
$ports[] = array('normal',  'TCP', '8000',  'Proxy/8000');
$ports[] = array('normal',  'TCP', '8080',  'Proxy/8080');
$ports[] = array('normal',  'TCP', '8154',  'Filesync');
$ports[] = array('normal',  'TCP', '9091', 'Transmission Web');
$ports[] = array('normal',  'TCP', '10000', 'Webmin');
$ports[] = array('normal',  'TCP', '32400', 'Plex Media Server');
$ports[] = array('normal',  'TCP', '51413', 'Transmission');
$ports[] = array('normal',  'UDP', '51413', 'Transmission');
$ports[] = array('special', 'TCP', '1723',  'PPTP');
$ports[] = array('special', 'GRE', '',      'PPTP');
$ports[] = array('special', 'ipv6-crypt', '', 'IPsec');
$ports[] = array('special', 'ipv6-auth', '',  'IPsec');
$ports[] = array('portrange',  'UDP', '137:138',  'NetBIOS');
$ports[] = array('portrange',  'UDP', '5060:5061',  'SIP');
$ports[] = array('portrange',  'UDP', '10000:20000', 'RTP');
$ports[] = array('portrange',  'TCP', '60000:60999',  'Passive FTP');
