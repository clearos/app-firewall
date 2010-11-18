<?php

///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2004-2010 ClearFoundation
//
///////////////////////////////////////////////////////////////////////////////
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
///////////////////////////////////////////////////////////////////////////////
//
// TODO: many of the methods use ConvertProtocolName().  That's fine, but it
// is now possible to create a firewall with protocol GRE and port 123.  That
// is non-sensical.  Handle this validation issue in a sane way.
//
///////////////////////////////////////////////////////////////////////////////

/**
 * FirewallRule base class.
 *
 * @package ClearOS
 * @subpackage API
 * @author {@link http://www.clearfoundation.com/ ClearFoundation}
 * @license http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @copyright Copyright 2004-2010 ClearFoundation
 */

///////////////////////////////////////////////////////////////////////////////
// B O O T S T R A P
///////////////////////////////////////////////////////////////////////////////

$bootstrap = isset($_ENV['CLEAROS_BOOTSTRAP']) ? $_ENV['CLEAROS_BOOTSTRAP'] : '/usr/clearos/framework/shared';
require_once($bootstrap . '/bootstrap.php');

///////////////////////////////////////////////////////////////////////////////
// T R A N S L A T I O N S
///////////////////////////////////////////////////////////////////////////////

clearos_load_language('base');

///////////////////////////////////////////////////////////////////////////////
// D E P E N D E N C I E S
///////////////////////////////////////////////////////////////////////////////

clearos_load_library('base/Engine');
clearos_load_library('firewall/Firewall');

///////////////////////////////////////////////////////////////////////////////
// E X C E P T I O N  C L A S S E S
///////////////////////////////////////////////////////////////////////////////

/**
 * Firewall invalid rule exception.
 *
 * @package ClearOS
 * @subpackage API
 * @author {@link http://www.clearfoundation.com/ ClearFoundation}
 * @license http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @copyright Copyright 2004-2010 ClearFoundation
 */

class FirewallInvalidRuleException extends EngineException
{
	/**
	 * FirewallInvalidRuleException constructor.
	 *
	 * @param string $reason Validation error
	 * @param int $code error code
	 */

	public function __construct($reason, $code)
	{
		parent::__construct("Invalid firewall rule - $reason", $code);
	}
}

///////////////////////////////////////////////////////////////////////////////
// C L A S S
///////////////////////////////////////////////////////////////////////////////

/**
 * FirewallRule base class.
 *
 * @package ClearOS
 * @subpackage API
 * @author {@link http://www.clearfoundation.com/ ClearFoundation}
 * @license http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @copyright Copyright 2004-2010 ClearFoundation
 */

class FirewallRule extends Engine
{
	///////////////////////////////////////////////////////////////////////////
	// C O N S T A N T S
	///////////////////////////////////////////////////////////////////////////

	const INCOMING_ALLOW	= 0x00000001;	// Incoming allow; port/port range
	const INCOMING_BLOCK	= 0x00000002;	// Incoming block; host
	const OUTGOING_BLOCK	= 0x00000004;	// Outgoing block; host, port/range
	const FORWARD			= 0x00000008;	// Forward; port/port range
	const DMZ_PINHOLE		= 0x00000010;	// DMZ pinhole; host/port
	const DMZ_INCOMING		= 0x00000020;	// DMZ incoming; host/port
	const RESERVED_0		= 0x00000040;	// Reserved
	const ONE_TO_ONE		= 0x00000080;	// One-to-one NAT
	const PPTP_FORWARD		= 0x00000100;	// PPTP forward rule
	const MAC_FILTER		= 0x00000200;	// HW/MAC filter rule
	const SBR_PORT			= 0x00000400;	// SBR: by port
	const SBR_HOST			= 0x00000800;	// SBR: by host
	const BANDWIDTH_RATE	= 0x00001000;	// Bandwidth rate rule
	const BANDWIDTH_PRIO	= 0x00002000;	// Bandwidth priority rule
	const BANDWIDTH_BASIC	= 0x00004000;	// "Basic" bandwidth rule
	const RESERVED_1		= 0x00008000;	// Reserved
	const RESERVED_2		= 0x00010000;	// Reserved
	const RESERVED_3		= 0x00020000;	// Reserved
	const RESERVED_4		= 0x00040000;	// Reserved
	const RESERVED_5		= 0x00080000;	// Reserved
	const LOCAL_NETWORK		= 0x00100000;	// Create rule for local networks
	const EXTERNAL_ADDR		= 0x00200000;	// Create rule for external addr
	const PROXY_BYPASS		= 0x00400000;	// Web Proxy Bypass
	const L7FILTER_BYPASS	= 0x00800000;	// Layer7 Filter Bypass
	const MAC_SOURCE		= 0x01000000;	// HW/MAC source address
	const WIFI				= 0x02000000;	// Wireless rule
	const IFADDRESS			= 0x04000000;	// Interface address 'addr' field
	const IFNETWORK			= 0x08000000;	// Interface network 'addr' field
	const ENABLED			= 0x10000000;	// Rule is enabled
	const CUSTOM			= 0x20000000;	// Custom rule
	const RESERVED_6		= 0x40000000;	// Reserved
	const RESERVED_7		= 0x80000000;	// Do not use this bit!

	const PROTO_IP = 0;
	const PROTO_TCP = 6;
	const PROTO_UDP = 17;
	const PROTO_GRE = 47;
	const PROTO_ESP = 50;
	const PROTO_AH = 51;

	///////////////////////////////////////////////////////////////////////////
	// V A R I A B L E S
	///////////////////////////////////////////////////////////////////////////

	protected $name = null;
	protected $group = null;
	protected $flags = null;
	protected $proto = null;
	protected $addr = null;
	protected $port = null;
	protected $param = null;

	///////////////////////////////////////////////////////////////////////////
	// M E T H O D S
	///////////////////////////////////////////////////////////////////////////

	public function __construct() 
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		parent::__construct();


		$this->Reset();
	}

	/**
	 * Reset class field members to default state.
	 *
	 * @return void
	 */

	public function Reset()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$this->name = "";
		$this->group = "";
		$this->flags = 0;
		$this->proto = FirewallRule::PROTO_IP;
		$this->addr = "";
		$this->port = "";
		$this->param = "";
	}

	/**
	 * Return validated rule in packed format.
	 *
	 * Rule format, 7 fields with a pipe '|' delimiter:
	 * name|group|flags|proto|addr|port|param
	 *
	 * @return string Valid rule in packed format
	 */

	public function GetRule()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$rule = new FirewallRule();

		// Validate member data
		$rule->SetRule(sprintf("%s|%s|0x%08x|%d|%s|%s|%s",
			$this->name, $this->group, $this->flags, $this->proto,
			$this->addr, $this->port, $this->param));

		return sprintf("%s|%s|0x%08x|%d|%s|%s|%s",
			$this->name, $this->group, $this->flags,
			$this->proto, $this->addr, $this->port, $this->param);
	}

	/**
	 * Set class members from packed format input.
	 *
	 * Rule format, 7 fields seperated by a pipe '|' delimiter:
	 * name|group|flags|proto|addr|port|param
	 *
	 * @param string $input Packed firewall rule
	 * @return void
	 * @throws FirewallInvalidRuleException
	 */

	public function SetRule($input)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$this->Reset();

		$parts = explode("|", $input);

		// Check field count
		if (sizeof($parts) != 7)
			throw new FirewallInvalidRuleException(FIREWALLRULE_LANG_ERRMSG_INVALID_FORMAT, COMMON_WARNING);

		// Name
		if (strlen($parts[0])) $this->SetName($parts[0]);

		// Group name
		if (strlen($parts[1])) $this->SetGroup($parts[1]);

		// Flags (4-byte bitmask)
		$flags = 0;
		if (!sscanf($parts[2], "0x%08x", $flags))
			throw new FirewallInvalidRuleException(FIREWALLRULE_LANG_ERRMSG_INVALID_FLAG, COMMON_WARNING);

		$this->SetFlags($flags);

		// Protocol (integer, see /etc/protocols)
		$this->SetProtocol($parts[3]);

		// Address (Hostname, IPv4, IPv6(at some point), MAC/HW)
		if (strlen($parts[4])) $this->SetAddress($parts[4]);

		// Port address - TCP/UDP protocols only
		if (strlen($parts[5])) {
			if (strstr($parts[5], ":")) {
				list($from, $to) = explode(":", $parts[5]);
				$this->SetPortRange($from, $to);
			} else {
				$this->SetPort($parts[5]);
			}
		}

		// Optional rule parameter
		if (strlen($parts[6])) $this->SetParameter($parts[6]);
	}

	/**
	 * Get rule name.
	 *
	 * @return string Rule name
	 */

	public function GetName()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return $this->name;
	}

	/**
	 * Set rule name.
	 *
	 * @param string $val Firewall name value
	 * @return void
	 */

	public function SetName($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (!strlen($val) || $this->IsValidName($val))
			$this->name = $val;
		else
			$this->AddValidationError(FIREWALL_LANG_ERRMSG_INVALID_NAME, __METHOD__, __LINE__);
	}

	/**
	 * Get rule group name.
	 *
	 * @return string Firewall group name
	 */

	public function GetGroup()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return $this->group;
	}

	/**
	 * Set rule group name.
	 *
	 * @param string $val Firewall group name
	 * @return void
	 */

	public function SetGroup($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (!strlen($val) || $this->IsValidName($val)) {
			$this->group = $val;
			return;
		} else {
			$this->AddValidationError(FIREWALL_LANG_ERRMSG_INVALID_GROUP, __METHOD__, __LINE__);
			return;
		}
	}

	/**
	 * Returns type description.
	 *
	 * @return string a description of the type of rule
	 */

	public function GetTypeText()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// TODO: This is a temporary workaround - an end user will see 
		// something that makes sense for "outgoing" rules when egress mode
		// is enabled.

		$egressstate = false;

		if (file_exists(COMMON_CORE_DIR . "/api/FirewallOutgoing.class.php")) {
			require_once(COMMON_CORE_DIR . "/api/FirewallOutgoing.class.php");
			$outgoingfw = new FirewallOutgoing();
			$egressstate = $outgoingfw->GetEgressState();
		}

		if ($this->flags & FirewallRule::INCOMING_ALLOW)
			$type = FIREWALLRULE_LANG_TYPE_INCOMING_ALLOW;
		else if ($this->flags & FirewallRule::INCOMING_BLOCK)
			$type = FIREWALLRULE_LANG_TYPE_INCOMING_BLOCK;
		else if ($this->flags & FirewallRule::OUTGOING_BLOCK)
			$type = ($egressstate) ? FIREWALLRULE_LANG_TYPE_OUTGOING_ALLOW : FIREWALLRULE_LANG_TYPE_OUTGOING_BLOCK;
		else if ($this->flags & FirewallRule::FORWARD)
			$type = FIREWALLRULE_LANG_TYPE_PORT_FORWARD;
		else if ($this->flags & FirewallRule::DMZ_PINHOLE)
			$type = FIREWALLRULE_LANG_TYPE_DMZ_PINHOLE;
		else if ($this->flags & FirewallRule::DMZ_INCOMING)
			$type = FIREWALLRULE_LANG_TYPE_DMZ_INCOMING;
		else if ($this->flags & FirewallRule::ONE_TO_ONE)
			$type = FIREWALLRULE_LANG_TYPE_ONE_TO_ONE_NAT;
		else if ($this->flags & FirewallRule::PPTP_FORWARD)
			$type = FIREWALLRULE_LANG_TYPE_PORT_FORWARD;
		else if ($this->flags & FirewallRule::MAC_FILTER)
			$type = FIREWALLRULE_LANG_TYPE_MAC_FILTER_ALLOW;
		else if ($this->flags & FirewallRule::SBR_PORT)
			$type = FIREWALLRULE_LANG_TYPE_MULTIWAN_SOURCE_BASE_ROUTE;
		else if ($this->flags & FirewallRule::SBR_HOST)
			$type = FIREWALLRULE_LANG_TYPE_MULTIWAN_DESTINATION_PORT;
		else if ($this->flags & FirewallRule::BANDWIDTH_RATE)
			$type = FIREWALLRULE_LANG_TYPE_BANDWIDTH;
		else if ($this->flags & FirewallRule::BANDWIDTH_PRIO)
			$type = FIREWALLRULE_LANG_TYPE_BANDWIDTH;
		else if ($this->flags & FirewallRule::PROXY_BYPASS)
			$type = FIREWALLRULE_LANG_TYPE_PROXY_BYPASS;
		else if ($this->flags & FirewallRule::L7FILTER_BYPASS)
			$type = FIREWALLRULE_LANG_TYPE_L7FILTER_BYPASS;
		else
			$type = LOCALE_LANG_UNKNOWN;

		return $type;
	}

	/**
	 * Is rule enabled?
	 *
	 * @return boolean True if rule is enabled, false otherwise
	 */

	public function IsEnabled()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return $this->flags & FirewallRule::ENABLED;
	}


	/**
	 * Enable rule.
	 *
	 * @return boolean Previous rule state
	 */

	public function Enable()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$was = ($this->flags & FirewallRule::ENABLED) ? true : false;
		$this->flags |= FirewallRule::ENABLED;
		return $was;
	}


	/**
	 * Disable rule.
	 *
	 * @return boolean Previous rule state
	 */

	public function Disable()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$was = ($this->flags & FirewallRule::ENABLED) ? true : false;
		$this->flags &= ~FirewallRule::ENABLED;

		return $was;
	}

	/**
	 * Get rule type and flags.
	 *
	 * @return int flags Rule flags
	 */

	public function GetFlags()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return $this->flags;
	}

	/**
	 * Set rule type and flags.
	 *
	 * @param int $val Rule flags
	 * @return void
	 */

	public function SetFlags($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (gettype($val) != "integer" || !$this->IsValidFlags($val)) {
			$this->AddValidationError(FIREWALLRULE_LANG_ERRMSG_INVALID_TYPE, __METHOD__, __LINE__);
			return;
		}

		$this->flags = $val;
	}

	/**
	 * Get rule protocol.
	 *
	 * @return int protocol Rule numeric protocol
	 */

	public function GetProtocol()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return $this->proto;
	}

	/**
	 * Set rule protocol.
	 *
	 * @param int $val Rule numeric protocol
	 * @return void
	 */

	public function SetProtocol($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (!$this->IsValidProtocol($val)) {
			$this->AddValidationError(FIREWALLRULE_LANG_ERRMSG_INVALID_PROTO, __METHOD__, __LINE__);
			return;
		}

		if ($val == Firewall::CONSTANT_ALL_PROTOCOLS)
			return;

		$this->proto = $val;
	}

	/**
	 * Get rule address.
	 *
	 * return string address Rule address
	 */

	public function GetAddress()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return $this->addr;
	}

	/**
	 * Set rule address.
	 *
	 * @param string $val Rule address
	 * @return void
	 */

	public function SetAddress($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (!strlen($val) || (!$this->IsValidTarget($val) && !$this->IsValidMac($val))) {
			$this->AddValidationError(FIREWALLRULE_LANG_ERRMSG_INVALID_ADDR, __METHOD__, __LINE__);
			return;
		}

		$this->addr = $val;
	}

	/**
	 * Get rule port.
	 *
	 * @return int port Rule numeric port address
	 */

	public function GetPort()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return $this->port;
	}


	/**
	 * Set rule port.
	 *
	 * @param int $port port address
	 * @return void
	 */

	public function SetPort($port)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$firewall = new Firewall();

		if (! $firewall->IsValidPort(trim($port))) {
			$this->AddValidationError(FIREWALL_LANG_ERRMSG_PORT_INVALID, __METHOD__, __LINE__);
			return;
		}

		if (gettype($port == "integer") && $port == Firewall::CONSTANT_ALL_PORTS)
			$this->port = "";
		else
			$this->port = trim($port);
	}

	/**
	 * Set rule port range.
	 *
	 * @param int $from from port
	 * @param int $to to port
	 * @return void
	 */

	public function SetPortRange($from, $to)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$firewall = new Firewall();

		if (! $firewall->IsValidPortRange($from, $to)) {
			$this->AddValidationError(FIREWALL_LANG_ERRMSG_PORT_RANGE_INVALID, __METHOD__, __LINE__);
			return;
		}

		$this->port = trim($from) . ":" . trim($to);
	}

	/**
	 * Get rule parameter value.
	 *
	 * @return mixed param Rule parameter field
	 */

	public function GetParameter()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return $this->param;
	}

	/**
	 * Set rule parameter value.
	 *
	 * @param mixed $val Rule parameter value
	 * @return void
	 */

	public function SetParameter($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$this->param = $val;
		return true;
	}

	/**
	 * Returns protocol flag for given protocol name.
	 *
	 * @param string $protocol protocol name
	 * @return flag protocol flag
	 */

	public function ConvertProtocolName($protocol)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		switch ($protocol) {

			case "TCP":
				$protocolflag = FirewallRule::PROTO_TCP;
				break;

			case "UDP":
				$protocolflag = FirewallRule::PROTO_UDP;
				break;

			case "GRE":
				$protocolflag = FirewallRule::PROTO_GRE;
				break;

			case "ESP":
			case "ipv6-crypt":
				$protocolflag = FirewallRule::PROTO_ESP;
				break;

			case "AH":
			case "ipv6-auth":
				$protocolflag = FirewallRule::PROTO_AH;
				break;

			// TODO: clean up
			case "ALL":
				$protocolflag = Firewall::CONSTANT_ALL_PROTOCOLS;
				break;
		}

		return $protocolflag;
	}

	///////////////////////////////////////////////////////////////////////////
	// C O M P A R I S O N
	///////////////////////////////////////////////////////////////////////////

	/**
	 * Compare this object with another, return true if equal.
	 *
	 * @param object $val FirewallRule object to compare against
	 * @return boolean True if objects are equal
	 */

	public function IsEqual($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (!($val instanceof FirewallRule)) return false;

		$equal = true;
		$flags = $val->flags;

		if ($this->flags & FirewallRule::ENABLED)
			$val->flags |= FirewallRule::ENABLED;
		else
			$val->flags &= ~FirewallRule::ENABLED;

		if ($this->flags & FirewallRule::CUSTOM)
			$val->flags |= FirewallRule::CUSTOM;
		else
			$val->flags &= ~FirewallRule::CUSTOM;

		if ($val->flags != $this->flags) $equal = false;
		if ($val->proto != $this->proto) $equal = false;
		if ($val->addr != $this->addr) $equal = false;
		if ($val->port != $this->port) $equal = false;
		if ($val->param != $this->param) $equal = false;

		$val->flags = $flags;

		return $equal;
	}

	///////////////////////////////////////////////////////////////////////////
	// V A L I D A T I O N
	///////////////////////////////////////////////////////////////////////////

	/**
	 * Is the rule name (or group name) valid?
	 *
	 * @param string $name Firewall rule name
	 * @return boolean True if rule name is valid
	 */

	public function IsValidName($name)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return (eregi("^[A-Z0-9_.-]*$", $name)) ? true : false;
	}

	/**
	 * Do the rule flags make sense?
	 *
	 * @param int $flags Rule flags to validate
	 * @return boolean True if flags are valid
	 */

	public function IsValidFlags($flags)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (!$flags) return false;

		$ex_flag = false;

		if ($flags & FirewallRule::INCOMING_ALLOW) {
			$ex_flag = true;
			$flags &= ~FirewallRule::INCOMING_ALLOW;
		} else if ($flags & FirewallRule::INCOMING_BLOCK) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::INCOMING_BLOCK;
		} else if ($flags & FirewallRule::OUTGOING_BLOCK) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::OUTGOING_BLOCK;
		} else if ($flags & FirewallRule::FORWARD) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::FORWARD;
		} else if ($flags & FirewallRule::DMZ_PINHOLE) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::DMZ_PINHOLE;
		} else if ($flags & FirewallRule::DMZ_INCOMING) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::DMZ_INCOMING;
		} else if ($flags & FirewallRule::ONE_TO_ONE) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::ONE_TO_ONE;
		} else if ($flags & FirewallRule::PPTP_FORWARD) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::PPTP_FORWARD;
		} else if ($flags & FirewallRule::MAC_FILTER) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::MAC_FILTER;
		} else if ($flags & FirewallRule::SBR_PORT) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::SBR_PORT;
		} else if ($flags & FirewallRule::SBR_HOST) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::SBR_HOST;
		} else if ($flags & FirewallRule::BANDWIDTH_RATE) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::BANDWIDTH_RATE;
		} else if ($flags & FirewallRule::BANDWIDTH_PRIO) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::BANDWIDTH_PRIO;
		} else if ($flags & FirewallRule::PROXY_BYPASS) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::PROXY_BYPASS;
		} else if ($flags & FirewallRule::L7FILTER_BYPASS) {
			if ($ex_flag) return false; $ex_flag = true;
			$flags &= ~FirewallRule::L7FILTER_BYPASS;
		}

		$flags &= ~FirewallRule::MAC_SOURCE;
		$flags &= ~FirewallRule::WIFI;
		$flags &= ~FirewallRule::ENABLED;
		$flags &= ~FirewallRule::CUSTOM;
		$flags &= ~FirewallRule::BANDWIDTH_BASIC;
		$flags &= ~FirewallRule::LOCAL_NETWORK;
		$flags &= ~FirewallRule::EXTERNAL_ADDR;
		$flags &= ~FirewallRule::IFADDRESS;
		$flags &= ~FirewallRule::IFNETWORK;

		if($flags != 0) return false;

		return true;
	}

	/**
	 * Is the rule protocol valid/supported?
	 *
	 * @param int $proto Numeric port address to validate
	 * @return boolean True if numeric port address is valid
	 */

	public function IsValidProtocol($proto)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if ($proto == Firewall::CONSTANT_ALL_PROTOCOLS)
			return true;

		if (gettype($proto) != "integer") {
			if (!ereg("^[0-9]{1,3}$", $proto)) return false;
			settype($proto, "integer");
		}

		switch ($proto) {
		case FirewallRule::PROTO_IP:
		case FirewallRule::PROTO_TCP:
		case FirewallRule::PROTO_UDP:
		case FirewallRule::PROTO_GRE:
		case FirewallRule::PROTO_ESP:
		case FirewallRule::PROTO_AH:
			return true;
		}

		return false;
	}

	/**
	 * Validation routine for IPs.
	 *
	 * @param string ip IP address
	 * @return boolean true if IP address is valid
	 */

	public function IsValidIp($ip)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$parts = explode(".", $ip);

		if (sizeof($parts) != 4) return false;

		foreach ($parts as $part) {
			if (!is_numeric($part) || ($part > 255) || ($part < 0))
				return false;
		}

		return true;
	}

	/**
	 * Is this (hostname, IPv4, and soon IPv6) address valid?
	 * localhost || 192.168.0.1 || 192.168.0.1/24 || 192.168.0.1/255.255.255.0 || 192.168.0.1:192.168.1.1
	 *
	 * TODO: hostname validation should be moved to IsValidHostname
	 * TODO: network validation should be moved to IsValidNetwork
	 * TODO: this class should extend Network() and use the standard validation
	 *
	 * @param string $ip hostname, IPv4 address to validate
	 * @return boolean True if address is valid
	 */

	public function IsValidTarget($ip)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$parts = array();
		
		if( ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", $ip, $parts) &&
			($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255)) return true;
		else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,3})$", $ip, $parts) &&
			($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 && $parts[5] < 32 && $parts[5] >= 8)) return true;
		else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$",
			$ip, $parts) && ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 &&
			$parts[5] <= 255 && $parts[6] <= 255 && $parts[7] <= 255 && $parts[8] <= 255)) return true;
		else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$",
			$ip, $parts) && ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 &&
			$parts[5] <= 255 && $parts[6] <= 255 && $parts[7] <= 255 && $parts[8] <= 255))
		{
			list($lo, $hi) = explode(":", $ip);
			if (ip2long($lo) < ip2long($hi)) return true;
		}
		// TODO: IPv6...
		else if (eregi("^[A-Z0-9.-]*$", $ip)) return true;

		return false;
	}

	/**
	 * Is this (MAC/HW) address valid? (eg AA:BB:CC:DD:EE:FF)
	 *
	 * @param string $mac Hardware address to validate
	 * @return boolean True if hardware address is valid
	 */

	public function IsValidMac($mac)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (eregi("^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$", $mac)) return true;
		return false;
	}

	/**
	 * Validates TCP port.
	 *
	 * @param integer $port port address
	 * @return boolean true if port address is valid
	 */

	public function IsValidPort($port)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if ($port == Firewall::CONSTANT_ALL_PORTS)
			return true;

		if (ereg("^[0-9]{1,5}$", $port))
			return true;

		if (ereg("^[0-9]{1,5}:[0-9]{1,5}$", $port)) {
			list($lo, $hi) = split(":", $port);
			if ($lo < $hi) return true;
		}

		return false;
	}

	/**
	 * @access private
	 */

	public function __destruct()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		parent::__destruct();
	}
}

// vi: ts=4
?>
