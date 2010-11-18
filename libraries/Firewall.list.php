<?php

///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2002-2006 Point Clark Networks.
//
///////////////////////////////////////////////////////////////////////////////

/**
 * Firewall list.
 *
 * The port list below describes all we need to now about a particular
 * service/port:
 * - the type (normal/special... see next note)
 * - the protocol
 * - the port (TCP/UDP protocols only care about this)
 * - a human readable name
 *
 * A user expects to see thins like "allow PPTP connections" in the default 
 * list of services.  They don't care that we have to do things differently
 * in the firewall.  The firewall class will handle thies special cases.
 *
 * @package Api
 * @subpackage Network
 * @author {@link http://www.pointclark.net/ Point Clark Networks}
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @copyright Copyright 2003-2006, Point Clark Networks
 */

$PORTS = array();
$PORTS[] = array("normal",  "TCP", "20",    "FTP");
$PORTS[] = array("normal",  "TCP", "21",    "FTP");
$PORTS[] = array("normal",  "TCP", "22",    "SSH");
$PORTS[] = array("normal",  "TCP", "25",    "SMTP");
$PORTS[] = array("normal",  "TCP", "80",    "HTTP");
$PORTS[] = array("normal",  "TCP", "81",    "Webconfig");
$PORTS[] = array("normal",  "TCP", "83",    "Webmail");
$PORTS[] = array("normal",  "TCP", "110",   "POP3");
$PORTS[] = array("normal",  "TCP", "113",   "Ident");
$PORTS[] = array("normal",  "UDP", "123",   "NTP");
$PORTS[] = array("normal",  "TCP", "143",   "IMAP");
$PORTS[] = array("normal",  "TCP", "443",   "HTTPS");
$PORTS[] = array("normal",  "TCP", "873",   "Rsync");
$PORTS[] = array("normal",  "TCP", "993",   "IMAPS");
$PORTS[] = array("normal",  "TCP", "995",   "POP3S");
$PORTS[] = array("normal",  "TCP", "1080",  "Proxy/SOCKS");
$PORTS[] = array("normal",  "UDP", "1194",  "OpenVPN");
$PORTS[] = array("normal",  "TCP", "1214",  "KaZaa/Morpheus");
$PORTS[] = array("normal",  "TCP", "1863",  "MSN");
$PORTS[] = array("normal",  "TCP", "1875",  "ClearSDN");
$PORTS[] = array("normal",  "TCP", "2121",  "Flexshare/FTP");
$PORTS[] = array("normal",  "TCP", "2123",  "Flexshare/FTPS");
$PORTS[] = array("normal",  "UDP", "4569",  "IAX2");
$PORTS[] = array("normal",  "UDP", "5050",  "BPALogin");
$PORTS[] = array("normal",  "TCP", "5190",  "ICQ/AIM");
$PORTS[] = array("normal",  "TCP", "6346",  "Gnutella");
$PORTS[] = array("normal",  "TCP", "6588",  "Proxy/AnalogX");
$PORTS[] = array("normal",  "TCP", "6667",  "IRC");
$PORTS[] = array("normal",  "TCP", "8000",  "Proxy/8000");
$PORTS[] = array("normal",  "TCP", "8080",  "Proxy/8080");
$PORTS[] = array("normal",  "TCP", "10000", "Webmin");
$PORTS[] = array("special", "TCP", "1723",  "PPTP");
$PORTS[] = array("special", "GRE", "",      "PPTP");
$PORTS[] = array("special", "ipv6-crypt", "", "IPsec");
$PORTS[] = array("special", "ipv6-auth", "",  "IPsec");
$PORTS[] = array("portrange",  "UDP", "5060:5061",  "SIP");
$PORTS[] = array("portrange",  "UDP", "10000:20000", "RTP");
$PORTS[] = array("portrange",  "TCP", "65000:65100",  "Passive FTP");

$DOMAINS = array();
$DOMAINS[] = array("update.microsoft.com", "Windows Update");

?>
