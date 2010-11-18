<?php

///////////////////////////////////////////////////////////////////////////////
//
// Copyright 2003-2010 ClearFoundation
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

/**
 * Firewall base class.
 *
 * @package ClearOS
 * @subpackage API
 * @author {@link http://www.clearfoundation.com/ ClearFoundation}
 * @license http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @copyright Copyright 2003-2010 ClearFoundation
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

clearos_load_library('base/Daemon');
clearos_load_library('base/File');
clearos_load_library('firewall/FirewallRule');
require_once("Firewall.list.php");

///////////////////////////////////////////////////////////////////////////////
// E X C E P T I O N  C L A S S E S
///////////////////////////////////////////////////////////////////////////////

/**
 * Firewall undefined role exception.
 *
 * @package ClearOS
 * @subpackage API
 * @author {@link http://www.clearfoundation.com/ ClearFoundation}
 * @license http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @copyright Copyright 2003-2010 ClearFoundation
 */

class FirewallUndefinedRoleException extends EngineException
{
	/**
	 * FirewallUndefinedRoleException constructor.
	 *
	 * @param string $role undefined role
	 * @param int $code error code
	 */

	public function __construct($role, $code)
	{
		parent::__construct("Undefined role - $role", $code);
	}
}

///////////////////////////////////////////////////////////////////////////////
// C L A S S
///////////////////////////////////////////////////////////////////////////////

/**
 * Firewall base class.
 *
 * @package ClearOS
 * @subpackage API
 * @author {@link http://www.clearfoundation.com/ ClearFoundation}
 * @license http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @copyright Copyright 2003-2010 ClearFoundation
 */

class Firewall extends Daemon
{
	///////////////////////////////////////////////////////////////////////////
	// C O N S T A N T S
	///////////////////////////////////////////////////////////////////////////

	const FILE_CONFIG = "/etc/firewall";
	const FILE_CUSTOM_RULES = "/etc/rc.d/rc.firewall.local";
	const CONSTANT_NOT_CONFIGURED = "notconfigured";
	const CONSTANT_ENABLED = "enabled";
	const CONSTANT_DISABLED = "disabled";
	const CONSTANT_ON = "on";
	const CONSTANT_OFF = "off";
	const CONSTANT_NORMAL = "normal";
	const CONSTANT_SPECIAL = "special";
	const CONSTANT_PORT_RANGE= "portrange";
	const CONSTANT_AUTO = 1;
	const CONSTANT_GATEWAY = "gateway";
	const CONSTANT_STANDALONE = "standalone";
	const CONSTANT_TRUSTEDSTANDALONE = "trustedstandalone";
	const CONSTANT_TRUSTEDGATEWAY = "trustedgateway";
	const CONSTANT_EXTERNAL = "EXTIF";
	const CONSTANT_DMZ = "DMZIF";
	const CONSTANT_LAN = "LANIF";
	const CONSTANT_HOT_LAN = "HOTIF";
	const CONSTANT_ALL_PORTS = 0;
	const CONSTANT_ALL_PROTOCOLS = "ALL";
	const CONSTANT_MULTIPATH = "MULTIPATH";
	const CONSTANT_PROTOCOL_UDP = "UDP";
	const CONSTANT_PROTOCOL_TCP = "TCP";
	// Number to start one-to-one NAT virtual IPs (i.e. eth0:200)
	const CONSTANT_ONE_TO_ONE_NAT_START = 200;

	///////////////////////////////////////////////////////////////////////////
	// V A R I A B L E S
	///////////////////////////////////////////////////////////////////////////

	///////////////////////////////////////////////////////////////////////////
	// M E T H O D S
	///////////////////////////////////////////////////////////////////////////

	/**
	 * Firewall constructor.
	 */

	public function __construct()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		parent::__construct("firewall");

	}

	/**
	 * Returns the pre-defined list of ports/and services.
	 *
	 * @return array list of pre-defined ports
	 */

	public function GetStandardServiceList()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		global $PORTS;

		// Some services (e.g. FTP) require more than one port definition.
		// This method basically returns the 4th bit of information in
		// our $PORTS array.
		$hashservices = array();
		$servicelist = array();

		foreach ($PORTS as $portinfo)
			$hashservices[$portinfo[3]] = true;

		while (list($key, $value) = each($hashservices))
			array_push($servicelist, $key);

		sort($servicelist);

		return $servicelist;
	}

	/**
	 * Returns the service defined by the given port/protocol.
	 *
	 * @param string protocol
	 * @param int port
	 * @return string service
	 */

	public function LookupService($protocol, $port)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		global $PORTS;

		foreach ($PORTS as $portinfo) {
			if (($portinfo[1] == $protocol) && ($portinfo[2] == $port))
				return $portinfo[3];
		}

		return null;
	}

	/**
	 * Returns the special name for a given host (eg ICQ servers).
	 *
	 * @param string host
	 * @return string name
	 */

	public function LookupHostMetainfo($host)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		global $DOMAINS;

		foreach ($DOMAINS as $hostinfo) {
			if ($hostinfo[0] == $host)
				return $hostinfo[1];
		}
	}

	/**
	 * Returns the current firewall mode.
	 *
	 * @return string firewall mode Firewall::CONSTANT_(AUTO, GATEWAY, or STANDALONE)
	 * @throws EngineException
	 */

	public function GetMode()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		try {
			$file = new File(Firewall::FILE_CONFIG);
			$retval = $file->LookupValue("/^MODE=/");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$retval = preg_replace("/\"/", "", $retval);
		$retval = preg_replace("/\s.*/", "", $retval);

		switch ($retval)
		{
		case "auto":
			return Firewall::CONSTANT_AUTO;
		case "gateway":
			return Firewall::CONSTANT_GATEWAY;
		case "standalone":
			return Firewall::CONSTANT_STANDALONE;
		case "trustedstandalone":
			return Firewall::CONSTANT_TRUSTEDSTANDALONE;
		case "trustedgateway":
			return Firewall::CONSTANT_TRUSTEDGATEWAY;
		}

		return Firewall::CONSTANT_AUTO;
	}

	/**
	 * Get network interface definition.  The firewall needs to know which
	 * interface performs which function.  If you pass the interface role
	 * into this method, it will return the interface (eg eth0).  The
	 * interface roles are defined as follows:
	 *
	 *  Firewall::CONSTANT_EXTERNAL
	 *  Firewall::CONSTANT_LAN
	 *  Firewall::CONSTANT_HOT_LAN
	 *  Firewall::CONSTANT_DMZ
	 * 
	 * Example:
	 *  GetInterfaceDefinition(Firewall::CONSTANT_LAN)
	 *  returns eth1 in most cases -- since this is the default.
	 *
	 * TODO: with multiple interfaces now allowed, we have to add
	 * a new method that will return a list.  For now, just return
	 * the first interface found.
	 *
	 * @param string role Interface role
	 * @return string interface Interface name
	 * @throws EngineException, ValidationException
	 */

	public function GetInterfaceDefinition($role)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if ($role == Firewall::CONSTANT_LAN) {
			$key = Firewall::CONSTANT_LAN;
			$default = "eth1";
		} else if ($role == Firewall::CONSTANT_HOT_LAN) {
			$key = Firewall::CONSTANT_HOT_LAN;
			$default = "eth1";
		} else if ($role == Firewall::CONSTANT_EXTERNAL) {
			$key = Firewall::CONSTANT_EXTERNAL;
			// If we see ppp0 defined, we assume it is either a DSL or dial-up
			// connection to the Internet.
			if (file_exists("/etc/sysconfig/network-scripts/ifcfg-ppp0"))
				$default = "ppp0";
			else
				$default = "eth0";
		} else if ($role == Firewall::CONSTANT_DMZ) {
			$key = Firewall::CONSTANT_DMZ;
			$default = "";
		} else
			throw new ValidationException("$role - " . LOCALE_LANG_ERRMSG_SYNTAX_ERROR);

		try {
			$file = new File(Firewall::FILE_CONFIG);
			$role = $file->LookupValue("/^$key=/");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$role = preg_replace("/\"/", "", $role);
		$role = preg_replace("/\s.*/", "", $role); // Only the first listed

		if ($role) return $role;

		return $default;
	}

	/**
	 * Get network interface role.  The firewall needs to know which
	 * interface performs which function.  If you pass the interface device
	 * into this method, it will return the interface's role.  The
	 * interface roles are defined as follows:
	 *
	 *  Firewall::CONSTANT_EXTERNAL
	 *  Firewall::CONSTANT_HOT_LAN
	 *  Firewall::CONSTANT_LAN
	 *  Firewall::CONSTANT_DMZ
	 *
	 * Example:
	 *  GetInterfaceRole("eth0")
	 *  returns Firewall::CONSTANT_LAN in most cases -- since this is the default.
	 *
	 * @param string device	Interface name
	 * @return string interface Interface role
	 * @throws EngineException
	 */

	public function GetInterfaceRole($device)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (strpos($device, ":") === false)
			$ifname = $device;
		else
			list($ifname, $unit) = split(":", $device, 5);

		$key = Firewall::CONSTANT_DMZ;

		try {
			$file = new File(Firewall::FILE_CONFIG);
			$iface = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$iface = preg_replace("/\"/", "", $iface);
		if (preg_match("/$ifname/", $iface)) return $key;

		$key = Firewall::CONSTANT_EXTERNAL;

		try {
			$iface = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e ) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$iface = preg_replace("/\"/", "", $iface);
		if (preg_match("/$ifname/", $iface)) return $key;

		$key = Firewall::CONSTANT_HOT_LAN;

		try {
			$iface = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e ) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$iface = preg_replace("/\"/", "", $iface);
		if (preg_match("/$ifname/", $iface)) return $key;

		return Firewall::CONSTANT_LAN;
	}

	/**
	 * Returns network interface role in text.
	 *
	 * @see GetInterfaceRole
	 * @param string $device interface name
	 * @return string interface role
	 * @throws EngineException
	 */

	public function GetInterfaceRoleText($device)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$role = $this->GetInterfaceRole($device);

		if ($role == Firewall::CONSTANT_LAN) {
			return FIREWALL_LANG_LAN;
		} else if ($role == Firewall::CONSTANT_EXTERNAL) {
			return FIREWALL_LANG_EXTERNAL;
		} else if ($role == Firewall::CONSTANT_DMZ) {
			return FIREWALL_LANG_MODE_DMZ;
		} else if ($role == Firewall::CONSTANT_HOT_LAN) {
			return FIREWALL_LANG_HOT_LAN;
		} else {
			return FIREWALL_LANG_LAN;
		}
	}

	/**
	 * Set network interface role.  The interface is first removed from it's
	 * previous role (if any).
	 *
	 * @param string device Interface name
	 * @param string role Interface role
	 * @return void
	 * @throws EngineException, FirewallUndefinedRoleException
	 */

	public function SetInterfaceRole($device, $role)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		if ($role != Firewall::CONSTANT_LAN) {
			try {
				$value = $file->LookupValue("/^" . Firewall::CONSTANT_LAN . "=/");
			} catch (FileNoMatchException $e) {
				throw new FirewallUndefinedRoleException(Firewall::CONSTANT_LAN, COMMON_WARNING);
			}

			$value = preg_replace("/\"/", "", $value);
			$list = explode(" ", $value);
			$value = "";

			foreach ($list as $iface) {
				if ($iface != $device) $value .= "$iface ";
			}

			$value = rtrim($value);

			try {
				$file->ReplaceLines("/^" . Firewall::CONSTANT_LAN . "=/i", Firewall::CONSTANT_LAN . "=\"$value\"\n");
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}
		}

		if ($role != Firewall::CONSTANT_HOT_LAN) {
			try {
				$value = $file->LookupValue("/^" . Firewall::CONSTANT_HOT_LAN . "=/");
			} catch (FileNoMatchException $e) {
				// throw new FirewallUndefinedRoleException(Firewall::CONSTANT_HOT_LAN, COMMON_WARNING);
			}

			$value = preg_replace("/\"/", "", $value);
			$list = explode(" ", $value);
			$value = "";

			foreach ($list as $iface) {
				if ($iface != $device) $value .= "$iface ";
			}

			$value = rtrim($value);

			try {
				$file->ReplaceLines("/^" . Firewall::CONSTANT_HOT_LAN . "=/i", Firewall::CONSTANT_HOT_LAN . "=\"$value\"\n");
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}
		}

		if ($role != Firewall::CONSTANT_EXTERNAL) {
			try {
				$value = $file->LookupValue("/^" . Firewall::CONSTANT_EXTERNAL . "=/");
			} catch (FileNoMatchException $e) {
				throw new FirewallUndefinedRoleException(Firewall::CONSTANT_EXTERNAL, COMMON_WARNING);
			}

			$value = preg_replace("/\"/", "", $value);
			$list = explode(" ", $value);
			$value = "";

			foreach ($list as $iface) {
				if ($iface != $device) $value .= "$iface ";
			}

			$value = rtrim($value);

			try {
				$file->ReplaceLines("/^" . Firewall::CONSTANT_EXTERNAL . "=/i", Firewall::CONSTANT_EXTERNAL . "=\"$value\"\n");
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}
		}

		if ($role != Firewall::CONSTANT_DMZ) {
			try {
				$value = $file->LookupValue("/^" . Firewall::CONSTANT_DMZ . "=/");
			} catch (FileNoMatchException $e) {
				throw new FirewallUndefinedRoleException(Firewall::CONSTANT_DMZ, COMMON_WARNING);
			}

			$value = preg_replace("/\"/", "", $value);
			$list = explode(" ", $value);
			$value = "";

			foreach ($list as $iface)
				if ($iface != $device) $value .= "$iface ";

			$value = rtrim($value);

			try {
				$file->ReplaceLines("/^" . Firewall::CONSTANT_DMZ . "=/i", Firewall::CONSTANT_DMZ . "=\"$value\"\n");
			} catch(Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}
		}

		try {
			$value = $file->LookupValue("/^$role=/");
		} catch (FileNoMatchException $e) {
			$value = "";

			try {
				$file->AddLinesAfter("$role=\n", "/^LANIF/");
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$value = preg_replace("/\"/", "", $value);
		$allifs = preg_split("/\s+/", $value);
		$allifs[] = $device;
		sort($allifs);
		$value = implode(" ", array_unique($allifs));
		$value = ltrim($value);

		try {
			$file->ReplaceLines("/^$role=/i", "$role=\"$value\"\n");
		} catch(EngineException $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Remove interface role.  The interface is removed from any role variables
	 * if it has been previously assigned a role.
	 *
	 * @param string device Interface name
	 * @return void
	 * @throws EngineException, FirewallUndefinedRoleException
	 */

	public function RemoveInterfaceRole($device)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$remove[] = $device;
		$file = new File(Firewall::FILE_CONFIG);

		for ($i = 0; $i < 4; $i++) {
			switch ($i) {
			case 0:
			default:
				$role = Firewall::CONSTANT_LAN;
				break;
			case 1:
				$role = Firewall::CONSTANT_HOT_LAN;
				break;
			case 2:
				$role = Firewall::CONSTANT_EXTERNAL;
				break;
			case 3:
				$role = Firewall::CONSTANT_DMZ;
			}

			try {
				$value = $file->LookupValue("/^$role=/");
			} catch (FileNoMatchException $e) {
				throw new FirewallUndefinedRoleException($role, COMMON_WARNING);
			}

			$value = trim(preg_replace("/\"/", "", $value));
			$value = implode(" ", array_diff(explode(" ", $value), $remove));

			try {
				$file->ReplaceLines("/^$role=/i", "$role=\"$value\"\n");
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}
		}
	}

	/**
	 * Get array of firewall rules.
	 *
	 * @return array rules FirewallRule objects
	 * @throws EngineException
	 */

	public function GetRules()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$rules = array();

		try {
			$file = new File(Firewall::FILE_CONFIG);
			$conf = $file->GetContents();
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$parts = array();
		
		if (eregi("RULES=\"([A-Z0-9|/_:.\\[:space:]-]*)\"", $conf, $parts) && strlen($parts[1])) {
			$value = trim(str_replace(array("\n", "\\", "\t"), " ", $parts[1]));
			while(strstr($value, "  ")) $value = str_replace("  ", " ", $value);

			if(!strlen($value)) return $rules;

			foreach(explode(" ", $value) as $rule)
			{
				$fwr = new FirewallRule();

				try {
					$fwr->SetRule($rule);
				} catch (FirewallInvalidRuleException $e) {
					continue;
				}

				$rules[] = $fwr;
			}
		}

		return $rules;
	}

	/**
	 * Set firewall rules from array.
	 *
	 * @param array rules Array of FirewallRule objects
	 * @return void
	 * @throws EngineException
	 */

	public function SetRules($rules)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$buffer = "";
		sort($rules);

		foreach ($rules as $rule) {
			$value = "";

			try {
				$value = $rule->GetRule();
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}

			$buffer .= sprintf("\t%s \\\n", $value);
		}

		$contents = null;
		$fw_conf = new File(Firewall::FILE_CONFIG);

		try {
			$contents = $fw_conf->GetContents();
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if (($conf = eregi_replace("RULES=\"[A-Z0-9|/_:.\\[:space:]-]*\"",
			"RULES=\"\\\n$buffer\"", $contents))) {

			$temp = new File("firewall", false, true);

			try {
				$temp->AddLines("$conf\n");
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}

			$fw_conf->Replace($temp->GetFilename());
		} else {
			throw new EngineException("Invalid firewall configuration", COMMON_WARNING);
		}
	}

	/**
	 * Find firewall rule.
	 *
	 * @param object val FirewallRule object to search for
	 * @return object Matching rule
	 */

	public function FindRule($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$rules = $this->GetRules();

		foreach ($rules as $rule)
			if ($val->IsEqual($rule)) return $rule;

		return null;
	}

	/**
	 * Add firewall rule.
	 *
	 * @param object val FirewallRule object to add
	 * @return void
	 * @throws EngineException
	 */

	public function AddRule($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		try {
			$val->GetRule();
			$rules = $this->GetRules();
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		foreach($rules as $rule)
		{
			if ($val->IsEqual($rule))
				throw new EngineException(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
		}

		$rules[] = $val;

		try {
			$this->SetRules($rules);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Delete firewall rule.
	 *
	 * @param object val FirewallRule object to delete
	 * @return void
	 * @throws EngineException
	 */

	public function DeleteRule($val)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		try {
			$val->GetRule();
			$old_rules = $this->GetRules();
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$exists = false;
		$new_rules = array();

		foreach ($old_rules as $rule) {
			if (!$val->IsEqual($rule)) {
				$new_rules[] = $rule;
				continue;
			}

			$exists = true;
		}

		if(!$exists) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_RULE_NOT_FOUND, COMMON_WARNING);
		}

		try {
			$this->SetRules($new_rules);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// G E N E R I C   M E T H O D S
	///////////////////////////////////////////////////////////////////////////

	/**
	 * Generic add MAC list.
	 *
	 * @param string mac MAC address
	 * @param string key key for the list
	 * @return void
	 * @throws EngineException
	 */

	protected function AddMac($mac, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $this->IsValidMac($mac)) {
			throw new EngineException("MAC - " . LOCALE_LANG_INVALID .
				" (AA:BB:CC:DD:EE:FF)", COMMON_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$maclist = $this->GetMacs($key);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if ($maclist) {
			foreach ($maclist as $macitem) {
				if ($macitem == $mac) {
					throw new EngineException(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
				}
				$thelist .= $macitem . " ";
			}
		}
		$thelist .= $mac;

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->ReplaceLines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->AddLines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic add for host, IP or network list.
	 *
	 * @param string host domain name, IP, or network address
	 * @param string key key for the list
	 * @return void
	 * @throws EngineException
	 */

	protected function AddHost($host, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $host) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_HOST_INVALID, COMMON_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$hostlist = $this->GetHosts($key);
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if ($hostlist) {
			foreach ($hostlist as $hostinfo) {
				if ($hostinfo[host] == $host) {
					throw new EngineException(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
				}
				$thelist .= $hostinfo[host] . " ";
			}
		}

		$thelist .= $host;

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->ReplaceLines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->AddLines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic add for a protocol/port list.
	 *
	 * @param string protocol the protocol - UDP/TCP
	 * @param string port service name, port number
	 * @param string key key for the list
	 * @return void
	 * @throws EngineException
	 */

	protected function AddPort($protocol, $port, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $this->IsValidProtocol($protocol)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, COMMON_WARNING);
		}

		if (! $this->IsValidPort($port)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_PORT_INVALID, COMMON_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$portlist = $this->GetPorts($key);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if ($portlist) {
			foreach ($portlist as $portinfo) {
				if (($portinfo[protocol] == $protocol) && ($portinfo[port] == $port)) {
					throw new EngineException(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
				}
				$thelist .= $portinfo[protocol] . "|" . $portinfo[port] . " ";
			}
		}
		$thelist .= "$protocol|$port";

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->ReplaceLines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->AddLines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic add for a protocol/port-range list.
	 *
	 * @param string protocol the protocol - UDP/TCP
	 * @param string from from service name, port number
	 * @param string to to service name, port number
	 * @param string key key for the list
	 * @return void
	 * @throws EngineException
	 */

	protected function AddPortRange($protocol, $from, $to, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $this->IsValidProtocol($protocol)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, COMMON_WARNING);
		}

		if (! $this->IsValidPortRange($from, $to)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_PORT_INVALID, COMMON_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$portlist = $this->GetPortRanges($key);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if ($portlist) {
			foreach ($portlist as $portinfo) {
				if (($portinfo[protocol] == $protocol) && ($portinfo[from] == $from) && ($portinfo[to] == $to)) {
					throw new EngineException(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
				}
				$thelist .= $portinfo[protocol] . "|" . $portinfo[from] . ":" . $portinfo[to] . " ";
			}
		}
		$thelist .= "$protocol|$from:$to";

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->ReplaceLines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->AddLines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic add for a protocol/port list - specified by service name.
	 *
	 * @param string service service name eg HTTP, FTP, SMTP
	 * @param string key key for the list
	 * @return void
	 * @throws EngineException
	 */

	protected function AddStandardService($service, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		global $PORTS;

		// Validate
		//---------

		if (! $this->IsValidService($service)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_SERVICE_INVALID, COMMON_WARNING);
		}

		$myports = $PORTS;
		foreach ($myports as $portinfo) {
			if ($portinfo[3] == $service) {

				if ($portinfo[0] == Firewall::CONSTANT_NORMAL) {
					try {
						$this->AddPort($portinfo[1], $portinfo[2], $key);
					} catch (Exception $e) {
						throw new EngineException($e->getMessage(), COMMON_WARNING);
					}	
				} else {
					throw new EngineException(LOCALE_LANG_ERRMSG_PARSE_ERROR, COMMON_WARNING);
				}
			}
		}
	}

	/**
	 * Generic delete for a host/IP/network list.
	 *
	 * @param string host host, IP or network
	 * @return void
	 * @throws EngineException
	 */

	protected function DeleteHost($host, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $host) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_HOST_INVALID, COMMON_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$hostlist = $this->GetHosts($key);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if ($hostlist) {
			foreach ($hostlist as $hostinfo) {
				if ($hostinfo[host] == $host) continue;
				$thelist .= "$hostinfo[host] ";
			}

			// Get rid of the last space added above
			$thelist = trim($thelist);
		}

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$match = $file->ReplaceLines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->AddLines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic delete for a MAC address.
	 *
	 * @param string mac MAC address
	 * @return void
	 * @throws EngineException
	 */

	protected function DeleteMac($mac, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $mac) {
			throw new EngineException("MAC - " . LOCALE_LANG_INVALID, COMMON_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$maclist = $this->GetMacs($key);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if ($maclist) {
			foreach ($maclist as $item) {
				if ($item == $mac) continue;
				$thelist .= "$item ";
			}

			// Get rid of the last space added above
			$thelist = trim($thelist);
		}

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->ReplaceLines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->AddLines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic delete for a protocol/port list.
	 *
	 * @param string protocol the protocol - UDP/TCP
	 * @param string port service name, port number
	 * @return void
	 * @throws EngineException
	 */

	protected function DeletePort($protocol, $port, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $this->IsValidProtocol($protocol)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, COMMON_WARNING);
		}

		if (! $this->IsValidPort($port)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_PORT_INVALID, COMMON_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$portlist = $this->GetPorts($key);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if ($portlist) {
			foreach ($portlist as $portinfo) {
				if (($portinfo[protocol] == $protocol) && ($portinfo[port] == $port))
					continue;
				$thelist .= $portinfo[protocol] . "|" . $portinfo[port] . " ";
			}

			// Get rid of the last space added above
			$thelist = trim($thelist);
		}

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->ReplaceLines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->AddLines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic delete for a protocol/port-range list.
	 *
	 * @param string protocol the protocol - UDP/TCP
	 * @param string port service name, port number
	 * @param string key key for the list
	 * @return void
	 * @throws EngineException
	 */

	protected function DeletePortRange($protocol, $from, $to, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $this->IsValidProtocol($protocol)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, COMMON_WARNING);
		}

		if (! $this->IsValidPortRange($from, $to)) {
			throw new EngineException(FIREWALL_LANG_ERRMSG_PORT_INVALID, COMMON_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$portlist = $this->GetPortRanges($key);
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		if ($portlist) {
			foreach ($portlist as $portinfo) {
				if (($portinfo[protocol] == $protocol) && ($portinfo[from] == $from) && ($portinfo[to] == $to))
					continue;
				$thelist .= $portinfo[protocol] . "|" . $portinfo[from] . ":" . $portinfo[to] . " ";
			}

			// Get rid of the last space added above
			$thelist = trim($thelist);
		}

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->ReplaceLines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->AddLines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic get list for a hosts or networks.
	 *
	 * @param string key key for the list
	 * @return array list of hosts
	 * @throws EngineException
	 */

	protected function GetHosts($key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$rawline = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
			return null;
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// - Get rid of quotes
		// - Make multiple spaces one single space
		$rawline = preg_replace("/\"/", "", $rawline);
		$rawline = preg_replace("/ +/", " ", $rawline);

		if (!$rawline) return null;

		$hostlist = array();
		$hostinfo = array();
		$itemlist = array();

		$itemlist = explode(" ", $rawline);
		foreach ($itemlist as $host) {
			$hostinfo[host] = $host;
			try {
				$hostinfo[metainfo] = $this->LookupHostMetainfo($host);
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}
			$hostlist[] = $hostinfo;
		}

		return $hostlist;
	}

	/**
	 * Generic get list for MAC addresses.
	 *
	 * @param string key key for the list
	 * @return array list of MACs
	 * @throws EngineException
	 */

	protected function GetMacs($key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$rawline = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
			return null;
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// - Get rid of quotes
		// - Make multiple spaces one single space
		$rawline = preg_replace("/\"/", "", $rawline);
		$rawline = preg_replace("/ +/", " ", $rawline);

		if (!$rawline) return null;

		$maclist = explode(" ", $rawline);

		return $maclist;
	}

	/**
	 * Generic get list for a protocol/port-range list.
	 * The information is an array with the following hash array entries:
	 *
	 *  info[protocol]
	 *  info[from]
	 *  info[to]
	 *
	 * @param string key key for the list
	 * @return array allowed incoming port ranges
	 */

	protected function GetPortRanges($key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$rawline = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
			return null;
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// - Get rid of quotes
		// - Make multiple spaces one single space
		$rawline = preg_replace("/\"/", "", $rawline);
		$rawline = preg_replace("/ +/", " ", $rawline);

		if (!$rawline) return;

		$portlist = array();
		$portinfo = array();
		$itemlist = array();

		$itemlist = explode(" ", $rawline);
		foreach ($itemlist as $item) {
			$details = explode("|", $item);
			$portinfo[protocol] = $details[0];
			$tofrom = explode(":", $details[1]);
			$portinfo[from] = $tofrom[0];
			$portinfo[to] = $tofrom[1];
			$portlist[] = $portinfo;
		}

		return $portlist;
	}

	/**
	 * Generic get list for a protocol/port list.
	 * The information is an array with the following hash array entries:
	 *
	 *  info[protocol]
	 *  info[port]
	 *  info[service] (FTP, HTTP, etc.)
	 *
	 * @param string key key for the list
	 * @return array allowed incoming ports
	 */

	protected function GetPorts($key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$rawline = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
			return null;
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// - Get rid of quotes
		// - Make multiple spaces one single space
		$rawline = preg_replace("/\"/", "", $rawline);
		$rawline = preg_replace("/ +/", " ", $rawline);

		if (!$rawline) return;

		$portlist = array();
		$portinfo = array();
		$itemlist = array();

		$itemlist = explode(" ", $rawline);
		foreach ($itemlist as $item) {
			$details = explode("|", $item);
			$portinfo[protocol] = $details[0];
			$portinfo[port] = $details[1];

			try {
				$portinfo[service] = $this->LookupService($portinfo[protocol], $portinfo[port]);
			} catch (Exception $e) {
				throw new EngineException($e->getMessage(), COMMON_WARNING);
			}

			$portlist[] = $portinfo;
		}

		return $portlist;
	}

	/**
	 * Generic get state for a on/off key.
	 *
	 * @param string key key for the list
	 * @return boolean state of the key
	 * @throws EngineException
	 */

	protected function GetState($key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$retval = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
			return false;
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$retval = preg_replace("/\"/", "", $retval);

		if (!$retval || ($retval == Firewall::CONSTANT_OFF)) {
			return false;
		} else if ($retval == Firewall::CONSTANT_ON) return true;

		return false;
	}

	/**
	 * Generic get value for a key.
	 *
	 * @param string key key for the list
	 * @return string value of the key
	 * @throws EngineException
	 */

	protected function GetValue($key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$retval = $file->LookupValue("/^$key=/");
		} catch (FileNoMatchException $e) {
			return null;
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		$retval = preg_replace("/\"/", "", $retval);
		$retval = preg_replace("/\s.*/", "", $retval);

		return $retval;
	}

	/**
	 * Generic set firewall mode.
	 *
	 * @param string mode Firewall mode
	 * @return void
	 * @throws EngineException
	 */

	public function SetMode($mode)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (! $this->IsValidMode($mode))
			throw new EngineException(FIREWALL_LANG_MODE . " - " . LOCALE_LANG_INVALID, COMMON_WARNING);

		$this->SetValue($mode, "MODE");
	}

	/**
	 * Generic set state for a on/off key.
	 *
	 * @param string $interface interface device name
	 * @param string $key value of the key
	 * @return void
	 * @throws EngineException
	 */

	protected function SetInterface($interface, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		// TODO

		// Update tag if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->ReplaceLines("/^$key=/", "$key=\"$interface\"\n");
		} catch (FileNoMatchException $e) {
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}

		// If tag does not exist, add it
		//------------------------------

		try {
			$file->AddLinesAfter("$key=\"$interface\"\n", "/^[^#]/");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic set state for a on/off key.
	 *
	 * @param boolean $state state true or false
	 * @param string $key key value of the key
	 * @throws EngineException
	 */

	protected function SetState($state, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! is_bool($state)) {
			throw new EngineException(LOCALE_LANG_ERRMSG_INVALID_TYPE, COMMON_WARNING);
		}

		// Update tag if it exists
		//------------------------

		if ($state)
			$flag = Firewall::CONSTANT_ON;
		else
			$flag = Firewall::CONSTANT_OFF;

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$match = $file->ReplaceLines("/^$key=/", "$key=\"$flag\"\n");
			if (! $match)
				$file->AddLinesAfter("$key=\"$flag\"\n", "/^[^#]/");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	/**
	 * Generic set for a miscelleanous value.
	 *
	 * @param string $value value of the key
	 * @param string $key key name
	 * @return void
	 * @throws EngineException
	 */

	protected function SetValue($value, $key)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// Update tag if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$match = $file->ReplaceLines("/^$key=/", "$key=\"$value\"\n");
			if (! $match)
				$file->AddLinesAfter("$key=\"$value\"\n", "/^[^#]/");
		} catch (Exception $e) {
			throw new EngineException($e->getMessage(), COMMON_WARNING);
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// V A L I D A T I O N   R O U T I N E S
	///////////////////////////////////////////////////////////////////////////

	/**
	 * Validation routine for IPs
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
	 * Validation routine for firewall mode.
	 *
	 * @param string mode Firewall mode
	 * @return boolean true if mode is valid
	 */

	public function IsValidMode($mode)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		switch($mode) {
		case Firewall::CONSTANT_GATEWAY:
		case Firewall::CONSTANT_STANDALONE:
		case Firewall::CONSTANT_TRUSTEDSTANDALONE:
		case Firewall::CONSTANT_TRUSTEDGATEWAY:
			return true;
		}

		return false;
	}

	/**
	 * Validation routine for MACs
	 *
	 * @param string mac MAC address
	 * @return boolean true if MAC address is valid
	 */

	public function IsValidMac($mac)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		// sample: 00:02:2D:53:2B:84
		$parts = explode(":", $mac);

		if (sizeof($parts) != 6) return false;

		foreach ($parts as $part) {
			if (strlen($part) != 2) return false;
		}

		return true;
	}

	/**
	 * Validation routine for integer port address
	 *
	 * @param int port Numeric port address
	 * @return boolean true if port is valid
	 */

	public function IsValidPort($port)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (! preg_match("/^\d+$/", $port))
			return false;

		// TODO: DMZ uses 0 as a flag for "all"
		if (($port > 65535) || ($port < 0))
			return false;

		return true;
	}

	/**
	 * Validation routine for integer port range
	 *
	 * @param int from Low port address
	 * @param int to High port address
	 * @return boolean true if port range is valid
	 */

	public function IsValidPortRange($from, $to)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if ((! preg_match("/^\d+$/", $from)) || (! preg_match("/^\d+$/", $to)))
			return false;

		if (($from > 65535) || ($from <= 0) || ($to > 65535) || ($to <= 0))
			return false;

		if ($from > $to)
			return false;

		return true;
	}

	/**
	 * Validation routine for protocol (TCP, UDP, ALL)
	 *
	 * @param string protocol Protocol (TCP, UDP, or ALL)
	 * @return boolean true if protocl is valid
	 */

	public function IsValidProtocol($protocol)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		if (preg_match("/^(TCP|UDP|ALL)$/", $protocol)) 
			return true;

		return false;
	}

	/**
	 * Validation routine for service.
	 *
	 * @param string service service eg HTTP
	 * @return boolean true if service is valid
	 */

	public function IsValidService($service)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		$servicelist = $this->GetStandardServiceList();
		foreach ($servicelist as $item) {
			if ($service == $item) return true;
		}
		return false;
	}

	/**
	 * Validation routine for IPSec Server
	 *
	 * @param boolean ipsecserver IPSec server toggle setting (true/false)
	 * @return boolean true if ipsecserver is valid
	 */

	public function IsValidServer($ipsecserver)
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		return (is_bool($ipsecserver));
	}

	/**
	 * @ignore
	 */

	public function __destruct()
	{
		ClearOsLogger::Profile(__METHOD__, __LINE__);

		parent::__destruct();
	}
}

// vi: ts=4
