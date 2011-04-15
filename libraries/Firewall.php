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
// N A M E S P A C E
///////////////////////////////////////////////////////////////////////////////

namespace clearos\apps\firewall;

///////////////////////////////////////////////////////////////////////////////
// B O O T S T R A P
///////////////////////////////////////////////////////////////////////////////

$bootstrap = isset($_ENV['CLEAROS_BOOTSTRAP']) ? $_ENV['CLEAROS_BOOTSTRAP'] : '/usr/clearos/framework/shared';
require_once($bootstrap . '/bootstrap.php');

///////////////////////////////////////////////////////////////////////////////
// T R A N S L A T I O N S
///////////////////////////////////////////////////////////////////////////////

clearos_load_language('base');
clearos_load_language('network');
clearos_load_language('firewall');

///////////////////////////////////////////////////////////////////////////////
// D E P E N D E N C I E S
///////////////////////////////////////////////////////////////////////////////

// Classes
//--------

use \clearos\apps\base\Engine as Engine;
use \clearos\apps\base\File as File;
use \clearos\apps\base\Daemon as Daemon;
use \clearos\apps\network\Network_Utils as Network_Utils;
use \clearos\apps\network\Firewall_Rule as Firewall_Rule;

clearos_load_library('base/Engine');
clearos_load_library('base/File');
clearos_load_library('base/Daemon');
clearos_load_library('network/Network_Utils');
clearos_load_library('firewall/Firewall_Rule');

require_once('Firewall.list.php');

// Exceptions
//-----------

use \clearos\apps\base\Validation_Exception as Validation_Exception;
use \clearos\apps\base\Engine_Exception as Engine_Exception;

clearos_load_library('base/Validation_Exception');

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

class Firewall_Undefined_Role_Exception extends Engine_Exception
{
	/**
	 * Firewall_Undefined_Role_Exception constructor.
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

	const FILE_CONFIG = '/etc/firewall';
	const FILE_CUSTOM_RULES = '/etc/rc.d/rc.firewall.local';
	const CONSTANT_NOT_CONFIGURED = 'notconfigured';
	const CONSTANT_ENABLED = 'enabled';
	const CONSTANT_DISABLED = 'disabled';
	const CONSTANT_ON = 'on';
	const CONSTANT_OFF = 'off';
	const CONSTANT_NORMAL = 'normal';
	const CONSTANT_SPECIAL = 'special';
	const CONSTANT_PORT_RANGE= 'portrange';
	const CONSTANT_AUTO = 1;
	const CONSTANT_GATEWAY = 'gateway';
	const CONSTANT_STANDALONE = 'standalone';
	const CONSTANT_TRUSTEDSTANDALONE = 'trustedstandalone';
	const CONSTANT_TRUSTEDGATEWAY = 'trustedgateway';
	const CONSTANT_EXTERNAL = 'EXTIF';
	const CONSTANT_DMZ = 'DMZIF';
	const CONSTANT_LAN = 'LANIF';
	const CONSTANT_HOT_LAN = 'HOTIF';
	const CONSTANT_ALL_PORTS = 0;
	const CONSTANT_ALL_PROTOCOLS = 'ALL';
	const CONSTANT_MULTIPATH = 'MULTIPATH';
	const CONSTANT_PROTOCOL_UDP = 'UDP';
	const CONSTANT_PROTOCOL_TCP = 'TCP';
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
		clearos_profile(__METHOD__, __LINE__);

		parent::__construct('firewall');
	}

	/**
	 * Returns the pre-defined list of ports/and services.
	 *
	 * @return array list of pre-defined ports
	 */

	public function get_standard_service_list()
	{
		clearos_profile(__METHOD__, __LINE__);

		global $PORTS;

		// Some services (e.g. FTP) require more than one port definition.
		// This method basically returns the 4th bit of information in
		// our $PORTS array.
		$hashservices = array();
		$servicelist = array();

		foreach ($PORTS as $portinfo)
			$hashservices[$portinfo[3]] = TRUE;

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
		clearos_profile(__METHOD__, __LINE__);

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

	public function lookup_host_metainfo($host)
	{
		clearos_profile(__METHOD__, __LINE__);

		global $DOMAINS;

		foreach ($DOMAINS as $hostinfo) {
			if ($hostinfo[0] == $host)
				return $hostinfo[1];
		}
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
	 *  get_interface_definition(Firewall::CONSTANT_LAN)
	 *  returns eth1 in most cases -- since this is the default.
	 *
	 * TODO: with multiple interfaces now allowed, we have to add
	 * a new method that will return a list.  For now, just return
	 * the first interface found.
	 *
	 * @param string role Interface role
	 * @return string interface Interface name
	 * @throws Engine_Exception, ValidationException
	 */

	public function get_interface_definition($role)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if ($role == Firewall::CONSTANT_LAN) {
			$key = Firewall::CONSTANT_LAN;
			$default = 'eth1';
		} else if ($role == Firewall::CONSTANT_HOT_LAN) {
			$key = Firewall::CONSTANT_HOT_LAN;
			$default = 'eth1';
		} else if ($role == Firewall::CONSTANT_EXTERNAL) {
			$key = Firewall::CONSTANT_EXTERNAL;
			// If we see ppp0 defined, we assume it is either a DSL or dial-up
			// connection to the Internet.
			if (file_exists('/etc/sysconfig/network-scripts/ifcfg-ppp0'))
				$default = 'ppp0';
			else
				$default = 'eth0';
		} else if ($role == Firewall::CONSTANT_DMZ) {
			$key = Firewall::CONSTANT_DMZ;
			$default = '';
		} else
			throw new ValidationException("$role - " . LOCALE_LANG_ERRMSG_SYNTAX_ERROR);

		try {
			$file = new File(Firewall::FILE_CONFIG);
			$role = $file->lookup_value("/^$key=/");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$role = preg_replace('/"/', '', $role);
		$role = preg_replace('/\s.*/', '', $role); // Only the first listed

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
	 *  get_interface_role("eth0")
	 *  returns Firewall::CONSTANT_LAN in most cases -- since this is the default.
	 *
	 * @param string device	Interface name
	 * @return string interface Interface role
	 * @throws Engine_Exception
	 */

	public function get_interface_role($device)
	{
		clearos_profile(__METHOD__, __LINE__);

		if (strpos($device, ':') === FALSE)
			$ifname = $device;
		else
			list($ifname, $unit) = split(':', $device, 5);

		$key = Firewall::CONSTANT_DMZ;

		try {
			$file = new File(Firewall::FILE_CONFIG);
			$iface = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$iface = preg_replace('/"/', '', $iface);
		if (preg_match("/$ifname/", $iface)) return $key;

		$key = Firewall::CONSTANT_EXTERNAL;

		try {
			$iface = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e ) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$iface = preg_replace('/"/', '', $iface);
		if (preg_match("/$ifname/", $iface)) return $key;

		$key = Firewall::CONSTANT_HOT_LAN;

		try {
			$iface = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e ) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$iface = preg_replace('/"/', '', $iface);
		if (preg_match("/$ifname/", $iface)) return $key;

		return Firewall::CONSTANT_LAN;
	}

	/**
	 * Returns network interface role in text.
	 *
	 * @see get_interface_role
	 * @param string $device interface name
	 * @return string interface role
	 * @throws Engine_Exception
	 */

	public function get_interface_role_text($device)
	{
		clearos_profile(__METHOD__, __LINE__);

		$role = $this->get_interface_role($device);

		if ($role == Firewall::CONSTANT_LAN) {
			return lang('firewall_lan');
		} else if ($role == Firewall::CONSTANT_EXTERNAL) {
			return lang('firewall_external');
		} else if ($role == Firewall::CONSTANT_DMZ) {
			return lang('firewall_dmz');
		} else if ($role == Firewall::CONSTANT_HOT_LAN) {
			return lang('firewall_hot_lan');
		} else {
			return lang('firewall_lan');
		}
	}

	/**
	 * Set network interface role.  The interface is first removed from it's
	 * previous role (if any).
	 *
	 * @param string device Interface name
	 * @param string role Interface role
	 * @return void
	 * @throws Engine_Exception, Firewall_Undefined_Role_Exception
	 */

	public function set_interfaceRole($device, $role)
	{
		clearos_profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		if ($role != Firewall::CONSTANT_LAN) {
			try {
				$value = $file->lookup_value('/^' . Firewall::CONSTANT_LAN . '=/');
			} catch (File_No_Match_Exception $e) {
				throw new Firewall_Undefined_Role_Exception(Firewall::CONSTANT_LAN, CLEAROS_WARNING);
			}

			$value = preg_replace('/"/', '', $value);
			$list = explode(' ', $value);
			$value = '';

			foreach ($list as $iface) {
				if ($iface != $device) $value .= "$iface ";
			}

			$value = rtrim($value);

			try {
				$file->replace_lines('/^' . Firewall::CONSTANT_LAN . '=/i',
                    Firewall::CONSTANT_LAN . "=\"$value\"\n");
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
			}
		}

		if ($role != Firewall::CONSTANT_HOT_LAN) {
			try {
				$value = $file->lookup_value('/^' . Firewall::CONSTANT_HOT_LAN . '=/');
			} catch (File_No_Match_Exception $e) {
				// throw new Firewall_Undefined_Role_Exception(Firewall::CONSTANT_HOT_LAN, CLEAROS_WARNING);
			}

			$value = preg_replace('/"/', '', $value);
			$list = explode(' ', $value);
			$value = '';

			foreach ($list as $iface) {
				if ($iface != $device) $value .= "$iface ";
			}

			$value = rtrim($value);

			try {
				$file->replace_lines('/^' . Firewall::CONSTANT_HOT_LAN . '=/i', Firewall::CONSTANT_HOT_LAN . "=\"$value\"\n");
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
			}
		}

		if ($role != Firewall::CONSTANT_EXTERNAL) {
			try {
				$value = $file->lookup_value('/^' . Firewall::CONSTANT_EXTERNAL . '=/');
			} catch (File_No_Match_Exception $e) {
				throw new Firewall_Undefined_Role_Exception(Firewall::CONSTANT_EXTERNAL, CLEAROS_WARNING);
			}

			$value = preg_replace('/"/', '', $value);
			$list = explode(' ', $value);
			$value = '';

			foreach ($list as $iface) {
				if ($iface != $device) $value .= "$iface ";
			}

			$value = rtrim($value);

			try {
				$file->replace_lines('/^' . Firewall::CONSTANT_EXTERNAL . '=/i', Firewall::CONSTANT_EXTERNAL . "=\"$value\"\n");
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
			}
		}

		if ($role != Firewall::CONSTANT_DMZ) {
			try {
				$value = $file->lookup_value('/^' . Firewall::CONSTANT_DMZ . '=/');
			} catch (File_No_Match_Exception $e) {
				throw new Firewall_Undefined_Role_Exception(Firewall::CONSTANT_DMZ, CLEAROS_WARNING);
			}

			$value = preg_replace('/"/', '', $value);
			$list = explode(' ', $value);
			$value = '';

			foreach ($list as $iface)
				if ($iface != $device) $value .= "$iface ";

			$value = rtrim($value);

			try {
				$file->replace_lines('/^' . Firewall::CONSTANT_DMZ . '=/i',
                    Firewall::CONSTANT_DMZ . "=\"$value\"\n");
			} catch(Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
			}
		}

		try {
			$value = $file->lookup_value("/^$role=/");
		} catch (File_No_Match_Exception $e) {
			$value = '';

			try {
				$file->add_lines_after("$role=\n", '/^LANIF/');
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
			}
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$value = preg_replace('/"/', '', $value);
		$allifs = preg_split('/\s+/', $value);
		$allifs[] = $device;
		sort($allifs);
		$value = implode(" ", array_unique($allifs));
		$value = ltrim($value);

		try {
			$file->replace_lines("/^$role=/i", "$role=\"$value\"\n");
		} catch(Engine_Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Remove interface role.  The interface is removed from any role variables
	 * if it has been previously assigned a role.
	 *
	 * @param string device Interface name
	 * @return void
	 * @throws Engine_Exception, Firewall_Undefined_Role_Exception
	 */

	public function remote_interface_role($device)
	{
		clearos_profile(__METHOD__, __LINE__);

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
				$value = $file->lookup_value("/^$role=/");
			} catch (File_No_Match_Exception $e) {
				throw new Firewall_Undefined_Role_Exception($role, CLEAROS_WARNING);
			}

			$value = trim(preg_replace("/\"/", '', $value));
			$value = implode(' ', array_diff(explode(' ', $value), $remove));

			try {
				$file->replace_lines("/^$role=/i", "$role=\"$value\"\n");
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
			}
		}
	}

	/**
	 * Get array of firewall rules.
	 *
	 * @return array rules Firewall_Rule objects
	 * @throws Engine_Exception
	 */

	public function get_rules()
	{
		clearos_profile(__METHOD__, __LINE__);

		$rules = array();

		try {
			$file = new File(Firewall::FILE_CONFIG);
			$conf = $file->get_contents();
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$parts = array();
		
		if (eregi("RULES=\"([A-Z0-9|/_:.\\[:space:]-]*)\"", $conf, $parts)
            && strlen($parts[1])) {
			$value = trim(
                str_replace(array("\n", "\\", "\t"), ' ', $parts[1]));
			while(strstr($value, '  '))
                $value = str_replace('  ', ' ', $value);

			if(!strlen($value)) return $rules;

			foreach(explode(' ', $value) as $rule)
			{
				$fwr = new Firewall_Rule();

				try {
					$fwr->set_rule($rule);
				} catch (Firewall_Invalid_Rule_Exception $e) {
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
	 * @param array rules Array of Firewall_Rule objects
	 * @return void
	 * @throws Engine_Exception
	 */

	public function set_rules($rules)
	{
		clearos_profile(__METHOD__, __LINE__);

		$buffer = '';
		sort($rules);

		foreach ($rules as $rule) {
			$value = '';

			try {
				$value = $rule->get_rule();
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
			}

			$buffer .= sprintf("\t%s \\\n", $value);
		}

		$contents = null;
		$fw_conf = new File(Firewall::FILE_CONFIG);

		try {
			$contents = $fw_conf->get_contents();
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		if (($conf = eregi_replace("RULES=\"[A-Z0-9|/_:.\\[:space:]-]*\"",
			"RULES=\"\\\n$buffer\"", $contents))) {

			$temp = new File("firewall", FALSE, TRUE);

			try {
				$temp->add_lines("$conf\n");
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
			}

			$fw_conf->Replace($temp->get_filename());
		} else {
			throw new Engine_Exception("Invalid firewall configuration", CLEAROS_WARNING);
		}
	}

	/**
	 * Find firewall rule.
	 *
	 * @param object val Firewall_Rule object to search for
	 * @return object Matching rule
	 */

	public function find_rule($val)
	{
		clearos_profile(__METHOD__, __LINE__);

		$rules = $this->get_rules();

		foreach ($rules as $rule)
			if ($val->is_equal($rule)) return $rule;

		return null;
	}

	/**
	 * Add firewall rule.
	 *
	 * @param object val Firewall_Rule object to add
	 * @return void
	 * @throws Engine_Exception
	 */

	public function add_rule($val)
	{
		clearos_profile(__METHOD__, __LINE__);

		try {
			$val->get_rule();
			$rules = $this->get_rules();
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		foreach($rules as $rule)
		{
			if ($val->is_equal($rule))
				throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, CLEAROS_WARNING);
		}

		$rules[] = $val;

		try {
			$this->set_rules($rules);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Delete firewall rule.
	 *
	 * @param object val Firewall_Rule object to delete
	 * @return void
	 * @throws Engine_Exception
	 */

	public function delete_rule($val)
	{
		clearos_profile(__METHOD__, __LINE__);

		try {
			$val->get_rule();
			$old_rules = $this->get_rules();
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$exists = FALSE;
		$new_rules = array();

		foreach ($old_rules as $rule) {
			if (!$val->is_equal($rule)) {
				$new_rules[] = $rule;
				continue;
			}

			$exists = TRUE;
		}

		if(!$exists) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_NOT_FOUND, CLEAROS_WARNING);
		}

		try {
			$this->set_rules($new_rules);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
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
	 * @throws Engine_Exception
	 */

	protected function add_mac($mac, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! Network_Utils::is_valid_mac($mac)) {
			throw new Engine_Exception("MAC - " . LOCALE_LANG_INVALID .
				" (AA:BB:CC:DD:EE:FF)", CLEAROS_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$maclist = $this->get_macs($key);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		if ($maclist) {
			foreach ($maclist as $macitem) {
				if ($macitem == $mac) {
					throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, CLEAROS_WARNING);
				}
				$thelist .= $macitem . " ";
			}
		}
		$thelist .= $mac;

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->add_lines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic add for host, IP or network list.
	 *
	 * @param string host domain name, IP, or network address
	 * @param string key key for the list
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function add_host($host, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $host) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_HOST_INVALID, CLEAROS_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$hostlist = $this->get_hosts($key);
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		if ($hostlist) {
			foreach ($hostlist as $hostinfo) {
				if ($hostinfo[host] == $host) {
					throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, CLEAROS_WARNING);
				}
				$thelist .= $hostinfo[host] . ' ';
			}
		}

		$thelist .= $host;

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->add_lines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic add for a protocol/port list.
	 *
	 * @param string protocol the protocol - UDP/TCP
	 * @param string port service name, port number
	 * @param string key key for the list
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function add_port($protocol, $port, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! Network_Utils::is_valid_protocol($protocol)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, CLEAROS_WARNING);
		}

		if (! Network_Utils::is_valid_port($port)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PORT_INVALID, CLEAROS_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$portlist = $this->get_ports($key);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		if ($portlist) {
			foreach ($portlist as $portinfo) {
				if (($portinfo[protocol] == $protocol) && ($portinfo[port] == $port)) {
					throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, CLEAROS_WARNING);
				}
				$thelist .= $portinfo[protocol] . '|' . $portinfo[port] . ' ';
			}
		}
		$thelist .= "$protocol|$port";

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->add_lines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
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
	 * @throws Engine_Exception
	 */

	protected function add_portRange($protocol, $from, $to, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! Network_Utils::is_valid_protocol($protocol)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, CLEAROS_WARNING);
		}

		if (! Network_Utils::is_valid_port_range($from, $to)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PORT_INVALID, CLEAROS_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$portlist = $this->get_port_ranges($key);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		if ($portlist) {
			foreach ($portlist as $portinfo) {
				if (($portinfo[protocol] == $protocol) && ($portinfo[from] == $from) && ($portinfo[to] == $to)) {
					throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, CLEAROS_WARNING);
				}
				$thelist .= $portinfo[protocol] . "|" . $portinfo[from] . ":" . $portinfo[to] . " ";
			}
		}
		$thelist .= "$protocol|$from:$to";

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->add_lines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic add for a protocol/port list - specified by service name.
	 *
	 * @param string service service name eg HTTP, FTP, SMTP
	 * @param string key key for the list
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function add_standard_service($service, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		global $PORTS;

		// Validate
		//---------

		if (! $this->is_valid_service($service)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_SERVICE_INVALID, CLEAROS_WARNING);
		}

		$myports = $PORTS;
		foreach ($myports as $portinfo) {
			if ($portinfo[3] == $service) {

				if ($portinfo[0] == Firewall::CONSTANT_NORMAL) {
					try {
						$this->add_port($portinfo[1], $portinfo[2], $key);
					} catch (Exception $e) {
						throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
					}	
				} else {
					throw new Engine_Exception(LOCALE_LANG_ERRMSG_PARSE_ERROR, CLEAROS_WARNING);
				}
			}
		}
	}

	/**
	 * Generic delete for a host/IP/network list.
	 *
	 * @param string host host, IP or network
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function delete_host($host, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $host) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_HOST_INVALID, CLEAROS_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$hostlist = $this->get_hosts($key);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		if ($hostlist) {
			foreach ($hostlist as $hostinfo) {
				if ($hostinfo[host] == $host) continue;
				$thelist .= $hostinfo[host] . ' ';
			}

			// Get rid of the last space added above
			$thelist = trim($thelist);
		}

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$match = $file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->add_lines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic delete for a MAC address.
	 *
	 * @param string mac MAC address
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function delete_mac($mac, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! $mac) {
			throw new Engine_Exception('MAC - ' . LOCALE_LANG_INVALID, CLEAROS_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$maclist = $this->get_macs($key);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
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
			$file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->add_lines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic delete for a protocol/port list.
	 *
	 * @param string protocol the protocol - UDP/TCP
	 * @param string port service name, port number
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function delete_port($protocol, $port, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! Network_Utils::is_valid_protocol($protocol)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, CLEAROS_WARNING);
		}

		if (! Network_Utils::is_valid_port($port)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PORT_INVALID, CLEAROS_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$portlist = $this->get_ports($key);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		if ($portlist) {
			foreach ($portlist as $portinfo) {
				if (($portinfo[protocol] == $protocol) && ($portinfo[port] == $port))
					continue;
				$thelist .= $portinfo[protocol] . '|' . $portinfo[port] . ' ';
			}

			// Get rid of the last space added above
			$thelist = trim($thelist);
		}

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->add_lines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic delete for a protocol/port-range list.
	 *
	 * @param string protocol the protocol - UDP/TCP
	 * @param string port service name, port number
	 * @param string key key for the list
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function delete_port_range($protocol, $from, $to, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! Network_Utils::is_valid_protocol($protocol)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, CLEAROS_WARNING);
		}

		if (! Network_Utils::is_valid_port_range($from, $to)) {
			throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PORT_INVALID, CLEAROS_WARNING);
		}

		// Grab the current list (if any)
		//-------------------------------

		try {
			$portlist = $this->get_port_ranges($key);
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		if ($portlist) {
			foreach ($portlist as $portinfo) {
				if (($portinfo[protocol] == $protocol) && ($portinfo[from] == $from) && ($portinfo[to] == $to))
					continue;
				$thelist .= $portinfo[protocol] . '|' . $portinfo[from] . ':' . $portinfo[to] . ' ';
			}

			// Get rid of the last space added above
			$thelist = trim($thelist);
		}

		// Update key if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If key does not exist, add it
		//------------------------------

		try {
			$file->add_lines("$key=\"$thelist\"\n");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic get list for a hosts or networks.
	 *
	 * @param string key key for the list
	 * @return array list of hosts
	 * @throws Engine_Exception
	 */

	protected function get_hosts($key)
	{
		clearos_profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$rawline = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
			return null;
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// - Get rid of quotes
		// - Make multiple spaces one single space
		$rawline = preg_replace('/"/', '', $rawline);
		$rawline = preg_replace('/ +/', ' ', $rawline);

		if (!$rawline) return null;

		$hostlist = array();
		$hostinfo = array();
		$itemlist = array();

		$itemlist = explode(' ', $rawline);
		foreach ($itemlist as $host) {
			$hostinfo[host] = $host;
			try {
				$hostinfo[metainfo] = $this->lookup_host_metainfo($host);
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
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
	 * @throws Engine_Exception
	 */

	protected function get_macs($key)
	{
		clearos_profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$rawline = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
			return null;
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// - Get rid of quotes
		// - Make multiple spaces one single space
		$rawline = preg_replace('/"/', '', $rawline);
		$rawline = preg_replace('/ +/', ' ', $rawline);

		if (!$rawline) return null;

		$maclist = explode(' ', $rawline);

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

	protected function get_port_ranges($key)
	{
		clearos_profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$rawline = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
			return null;
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// - Get rid of quotes
		// - Make multiple spaces one single space
		$rawline = preg_replace('/"/', '', $rawline);
		$rawline = preg_replace('/ +/', ' ', $rawline);

		if (!$rawline) return;

		$portlist = array();
		$portinfo = array();
		$itemlist = array();

		$itemlist = explode(' ', $rawline);
		foreach ($itemlist as $item) {
			$details = explode("|", $item);
			$portinfo[protocol] = $details[0];
			$tofrom = explode(':', $details[1]);
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

	protected function get_ports($key)
	{
		clearos_profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$rawline = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
			return null;
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// - Get rid of quotes
		// - Make multiple spaces one single space
		$rawline = preg_replace('/"/', '', $rawline);
		$rawline = preg_replace('/ +/', ' ', $rawline);

		if (!$rawline) return;

		$portlist = array();
		$portinfo = array();
		$itemlist = array();

		$itemlist = explode(' ', $rawline);
		foreach ($itemlist as $item) {
			$details = explode('|', $item);
			$portinfo[protocol] = $details[0];
			$portinfo[port] = $details[1];

			try {
				$portinfo[service] = $this->LookupService(
                    $portinfo[protocol], $portinfo[port]);
			} catch (Exception $e) {
				throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
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
	 * @throws Engine_Exception
	 */

	protected function get_state($key)
	{
		clearos_profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$retval = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
			return FALSE;
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$retval = preg_replace("/\"/", "", $retval);

		if (!$retval || ($retval == Firewall::CONSTANT_OFF)) {
			return FALSE;
		} else if ($retval == Firewall::CONSTANT_ON) return TRUE;

		return FALSE;
	}

	/**
	 * Generic get value for a key.
	 *
	 * @param string key key for the list
	 * @return string value of the key
	 * @throws Engine_Exception
	 */

	protected function get_value($key)
	{
		clearos_profile(__METHOD__, __LINE__);

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$retval = $file->lookup_value("/^$key=/");
		} catch (File_No_Match_Exception $e) {
			return null;
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		$retval = preg_replace("/\"/", "", $retval);
		$retval = preg_replace("/\s.*/", "", $retval);

		return $retval;
	}

	/**
	 * Generic set state for a on/off key.
	 *
	 * @param string $interface interface device name
	 * @param string $key value of the key
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function set_interface($interface, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		// TODO

		// Update tag if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$file->replace_lines("/^$key=/", "$key=\"$interface\"\n");
		} catch (File_No_Match_Exception $e) {
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}

		// If tag does not exist, add it
		//------------------------------

		try {
			$file->add_lines_after("$key=\"$interface\"\n", "/^[^#]/");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic set state for a on/off key.
	 *
	 * @param boolean $state state TRUE or FALSE
	 * @param string $key key value of the key
	 * @throws Engine_Exception
	 */

	protected function set_state($state, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Validate
		//---------

		if (! is_bool($state)) {
			throw new Engine_Exception(LOCALE_LANG_ERRMSG_INVALID_TYPE, CLEAROS_WARNING);
		}

		// Update tag if it exists
		//------------------------

		if ($state)
			$flag = Firewall::CONSTANT_ON;
		else
			$flag = Firewall::CONSTANT_OFF;

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$match = $file->replace_lines("/^$key=/", "$key=\"$flag\"\n");
			if (! $match)
				$file->add_lines_after("$key=\"$flag\"\n", "/^[^#]/");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	/**
	 * Generic set for a miscelleanous value.
	 *
	 * @param string $value value of the key
	 * @param string $key key name
	 * @return void
	 * @throws Engine_Exception
	 */

	protected function set_value($value, $key)
	{
		clearos_profile(__METHOD__, __LINE__);

		// Update tag if it exists
		//------------------------

		$file = new File(Firewall::FILE_CONFIG);

		try {
			$match = $file->replace_lines("/^$key=/", "$key=\"$value\"\n");
			if (! $match)
				$file->add_lines_after("$key=\"$value\"\n", "/^[^#]/");
		} catch (Exception $e) {
			throw new Engine_Exception($e->getMessage(), CLEAROS_WARNING);
		}
	}

	///////////////////////////////////////////////////////////////////////////
	// V A L I D A T I O N   R O U T I N E S
	///////////////////////////////////////////////////////////////////////////

	/**
	 * Validation routine for service.
	 *
	 * @param string service service eg HTTP
	 * @return boolean TRUE if service is valid
	 */

	public function is_valid_service($service)
	{
		clearos_profile(__METHOD__, __LINE__);

		$servicelist = $this->get_standard_service_list();
		foreach ($servicelist as $item)
			if ($service == $item) return TRUE;
		return FALSE;
	}

	/**
	 * Validation routine for IPSec Server
	 *
	 * @param boolean ipsecserver IPSec server toggle setting (TRUE/FALSE)
	 * @return boolean TRUE if ipsecserver is valid
	 */

	public function is_valid_server($ipsecserver)
	{
		clearos_profile(__METHOD__, __LINE__);

		return (is_bool($ipsecserver));
	}

}
