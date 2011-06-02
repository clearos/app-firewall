<?php

/**
 * Firewall class.
 *
 * @category   Apps
 * @package    Firewall
 * @subpackage Libraries
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2004-2011 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/firewall/
 */

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

///////////////////////////////////////////////////////////////////////////////
// N A M E S P A C E
///////////////////////////////////////////////////////////////////////////////

namespace clearos\apps\firewall;

///////////////////////////////////////////////////////////////////////////////
// B O O T S T R A P
///////////////////////////////////////////////////////////////////////////////

$bootstrap = getenv('CLEAROS_BOOTSTRAP') ? getenv('CLEAROS_BOOTSTRAP') : '/usr/clearos/framework/shared';
require_once $bootstrap . '/bootstrap.php';

///////////////////////////////////////////////////////////////////////////////
// T R A N S L A T I O N S
///////////////////////////////////////////////////////////////////////////////

clearos_load_language('base');

///////////////////////////////////////////////////////////////////////////////
// D E P E N D E N C I E S
///////////////////////////////////////////////////////////////////////////////

// Classes
//--------

use \clearos\apps\base\Daemon as Daemon;
use \clearos\apps\base\File as File;
use \clearos\apps\firewall\Firewall as Firewall;
use \clearos\apps\firewall\Firewall_Rule as Firewall_Rule;

clearos_load_library('base/Daemon');
clearos_load_library('base/File');
clearos_load_library('firewall/Firewall');
clearos_load_library('firewall/Firewall_Rule');

// Exceptions
//-----------

use \clearos\apps\base\Engine_Exception as Engine_Exception;
use \clearos\apps\base\File_No_Match_Exception as File_No_Match_Exception;
use \clearos\apps\base\File_Not_Found_Exception as File_Not_Found_Exception;
use \clearos\apps\base\Validation_Exception as Validation_Exception;
use \clearos\apps\firewall\Firewall_Invalid_Rule_Exception as Firewall_Invalid_Rule_Exception;
use \clearos\apps\firewall\Firewall_Undefined_Role_Exception as Firewall_Undefined_Role_Exception;

clearos_load_library('base/Engine_Exception');
clearos_load_library('base/File_No_Match_Exception');
clearos_load_library('base/File_Not_Found_Exception');
clearos_load_library('base/Validation_Exception');
clearos_load_library('firewall/Firewall_Invalid_Rule_Exception');
clearos_load_library('firewall/Firewall_Undefined_Role_Exception');

///////////////////////////////////////////////////////////////////////////////
// C L A S S
///////////////////////////////////////////////////////////////////////////////

/**
 * Firewall class.
 *
 * @category   Apps
 * @package    Firewall
 * @subpackage Libraries
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2004-2011 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/firewall/
 */

class Firewall extends Daemon
{
    ///////////////////////////////////////////////////////////////////////////
    // C O N S T A N T S
    ///////////////////////////////////////////////////////////////////////////

    // Files and paths
    const FILE_CONFIG = '/etc/firewall';
    const FILE_CUSTOM_RULES = '/etc/rc.d/rc.firewall.local';

    // Roles
    const ROLE_EXTERNAL = 'EXTIF';
    const ROLE_DMZ = 'DMZIF';
    const ROLE_LAN = 'LANIF';
    const ROLE_HOT_LAN = 'HOTIF';

    // Modes
    const MODE_GATEWAY = 'gateway';
    const MODE_STANDALONE = 'standalone';
    const MODE_TRUSTED_STANDALONE = 'trustedstandalone';
    const MODE_TRUSTED_GATEWAY = 'trustedgateway';

    // Protocols
    const PROTOCOL_UDP = 'UDP';
    const PROTOCOL_TCP = 'TCP';

    const CONSTANT_NOT_CONFIGURED = 'notconfigured';
    const CONSTANT_ENABLED = 'enabled';
    const CONSTANT_DISABLED = 'disabled';
    const CONSTANT_ON = 'on';
    const CONSTANT_OFF = 'off';
    const CONSTANT_NORMAL = 'normal';
    const CONSTANT_SPECIAL = 'special';
    const CONSTANT_PORT_RANGE = 'portrange';
    const CONSTANT_AUTO = 1;
    const CONSTANT_ALL_PORTS = 0;
    const CONSTANT_ALL_PROTOCOLS = 'ALL';
    const CONSTANT_MULTIPATH = 'MULTIPATH';
    const CONSTANT_ONE_TO_ONE_NAT_START = 200;

    ///////////////////////////////////////////////////////////////////////////
    // V A R I A B L E S
    ///////////////////////////////////////////////////////////////////////////

    protected $ports = array();
    protected $roles = array();
    protected $domains = array();

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

        include clearos_app_base('firewall') . '/deploy/ports.php';
        include clearos_app_base('firewall') . '/deploy/domains.php';

        $this->ports = $ports;
        $this->domains = $domains;
        $this->roles = array(
            Firewall::ROLE_LAN => lang('firewall_lan'),
            Firewall::ROLE_HOT_LAN => lang('firewall_hot_lan'),
            Firewall::ROLE_EXTERNAL => lang('firewall_external'),
            Firewall::ROLE_DMZ => lang('firewall_dmz'),
        );
    }

    /**
     * Returns the pre-defined list of ports/and services.
     *
     * @return array list of pre-defined ports
     */

    public function get_standard_service_list()
    {
        clearos_profile(__METHOD__, __LINE__);

        // Some services (e.g. FTP) require more than one port definition.
        // This method basically returns the 4th bit of information in
        // our $this->ports array.

        $hash_services = array();
        $service_list = array();

        foreach ($this->ports as $portinfo)
            $hash_services[$portinfo[3]] = TRUE;

        while (list($key, $value) = each($hash_services))
            array_push($service_list, $key);

        sort($service_list);

        return $service_list;
    }

    /**
     * Returns the service defined by the given port/protocol.
     *
     * @param string  protocol
     * @param integer port
     *
     * @return string service
     */

    public function lookup_service($protocol, $port)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($port));

        foreach ($this->ports as $port_info) {
            if (($port_info[1] == $protocol) && ($port_info[2] == $port))
                return $port_info[3];
        }
    }

    /**
     * Returns the special name for a given host (eg ICQ servers).
     *
     * @param string host
     *
     * @return string meta name
     */

    public function lookup_host_metainfo($host)
    {
        clearos_profile(__METHOD__, __LINE__);

        foreach ($this->domains as $host_info) {
            if ($host_info[0] === $host)
                return $host_info[1];
        }
    }

    /**
     * Returns network interface definition.
     *
     * The firewall needs to know which interface performs which role.
     * If you pass the interface role into this method, it will return the
     * interface (eg eth0).  The interface roles are defined as follows:
     *
     *  Firewall::ROLE_EXTERNAL
     *  Firewall::ROLE_LAN
     *  Firewall::ROLE_HOT_LAN
     *  Firewall::ROLE_DMZ
     * 
     * TODO: with multiple interfaces now allowed, we have to add
     * a new method that will return a list.  For now, just return
     * the first interface found.
     *
     * @param string $role interface role
     *
     * @return string interface name
     * @throws Engine_Exception, Validation_Exception
     */

    public function get_interface_definition($role)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_role($role));

        if ($role === Firewall::ROLE_LAN) {
            $key = Firewall::ROLE_LAN;
            $default = 'eth1';
        } else if ($role === Firewall::ROLE_HOT_LAN) {
            $key = Firewall::ROLE_HOT_LAN;
            $default = 'eth1';
        } else if ($role === Firewall::ROLE_EXTERNAL) {
            $key = Firewall::ROLE_EXTERNAL;
            // TODO: cleanup
            // If we see ppp0 defined, we assume it is either a DSL or dial-up
            // connection to the Internet.
            if (file_exists('/etc/sysconfig/network-scripts/ifcfg-ppp0'))
                $default = 'ppp0';
            else
                $default = 'eth0';
        } else if ($role === Firewall::ROLE_DMZ) {
            $key = Firewall::ROLE_DMZ;
            $default = '';
        }

        $file = new File(Firewall::FILE_CONFIG);

        try {
            $role = $file->lookup_value("/^$key=/");
        } catch (File_No_Match_Exception $e) {
            $role = '';
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e));
        }

        $role = preg_replace("/\"/", "", $role);
        $role = preg_replace("/\s.*/", "", $role); // Only the first listed

        if ($role)
            return $role;

        return $default;
    }

    /**
     * Returns network interface role.
     *
     * The firewall needs to know which interface performs which role. 
     * If you pass the interface device into this method, it will return the
     * interface's role.  The interface roles are defined as follows:
     *
     *  Firewall::ROLE_EXTERNAL
     *  Firewall::ROLE_HOT_LAN
     *  Firewall::ROLE_LAN
     *  Firewall::ROLE_DMZ
     *
     * @param string $device interface name
     *
     * @return string $interface network role
     * @throws Engine_Exception
     */

    public function get_interface_role($device)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (strpos($device, ":") === FALSE)
            $ifname = $device;
        else
            list($ifname, $unit) = split(":", $device, 5);

        $iface = '';
        $key = Firewall::ROLE_DMZ;

        try {
            $file = new File(Firewall::FILE_CONFIG);
            $iface = $file->lookup_value("/^$key=/");
        } catch (File_Not_Found_Exception $e) {
        } catch (File_No_Match_Exception $e) {
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e));
        }

        $iface = preg_replace("/\"/", "", $iface);

        if (preg_match("/$ifname/", $iface))
            return $key;

        $key = Firewall::ROLE_EXTERNAL;

        try {
            $iface = $file->lookup_value("/^$key=/");
        } catch (File_Not_Found_Exception $e) {
        } catch (File_No_Match_Exception $e) {
        } catch (Exception $e ) {
            throw new Engine_Exception(clearos_exception_message($e));
        }

        $iface = preg_replace("/\"/", "", $iface);
        if (preg_match("/$ifname/", $iface))
            return $key;

        $key = Firewall::ROLE_HOT_LAN;

        try {
            $iface = $file->lookup_value("/^$key=/");
        } catch (File_Not_Found_Exception $e) {
        } catch (File_No_Match_Exception $e) {
        } catch (Exception $e ) {
            throw new Engine_Exception(clearos_exception_message($e));
        }

        $iface = preg_replace("/\"/", "", $iface);

        if (preg_match("/$ifname/", $iface))
            return $key;

        return Firewall::ROLE_LAN;
    }

    /**
     * Returns network interface role in text.
     *
     * @see get_interface_role
     * @param string $device interface name
     *
     * @return string interface role
     * @throws Engine_Exception
     */

    public function get_interface_role_text($device)
    {
        clearos_profile(__METHOD__, __LINE__);

        $role = $this->get_interface_role($device);

        Validation_Exception::is_valid($this->validate_role($role));

        return $this->roles[$role];
    }

    /**
     * Set network interface role.  The interface is first removed from it's
     * previous role (if any).
     *
     * @param string device Interface name
     * @param string role Interface role
     *
     * @return void
     * @throws Engine_Exception, Firewall_Undefined_Role_Exception
     */

    public function set_interface_role($device, $role)
    {
        clearos_profile(__METHOD__, __LINE__);

        $file = new File(Firewall::FILE_CONFIG);

        if ($role != Firewall::ROLE_LAN) {
            try {
                $value = $file->lookup_value("/^" . Firewall::ROLE_LAN . "=/");
            } catch (File_No_Match_Exception $e) {
                throw new Firewall_Undefined_Role_Exception();
            }

            $value = preg_replace("/\"/", "", $value);
            $list = explode(" ", $value);
            $value = "";

            foreach ($list as $iface) {
                if ($iface != $device) $value .= "$iface ";
            }

            $value = rtrim($value);

            $file->replace_lines("/^" . Firewall::ROLE_LAN . "=/i", Firewall::ROLE_LAN . "=\"$value\"\n");
        }

        if ($role != Firewall::ROLE_HOT_LAN) {
            try {
                $value = $file->lookup_value("/^" . Firewall::ROLE_HOT_LAN . "=/");
            } catch (File_No_Match_Exception $e) {
                // throw new Firewall_Undefined_Role_Exception(Firewall::ROLE_HOT_LAN, COMMON_WARNING);
            }

            $value = preg_replace("/\"/", "", $value);
            $list = explode(" ", $value);
            $value = "";

            foreach ($list as $iface) {
                if ($iface != $device) $value .= "$iface ";
            }

            $value = rtrim($value);

            $file->replace_lines("/^" . Firewall::ROLE_HOT_LAN . "=/i", Firewall::ROLE_HOT_LAN . "=\"$value\"\n");
        }

        if ($role != Firewall::ROLE_EXTERNAL) {
            try {
                $value = $file->lookup_value("/^" . Firewall::ROLE_EXTERNAL . "=/");
            } catch (File_No_Match_Exception $e) {
                throw new Firewall_Undefined_Role_Exception();
            }

            $value = preg_replace("/\"/", "", $value);
            $list = explode(" ", $value);
            $value = "";

            foreach ($list as $iface) {
                if ($iface != $device) $value .= "$iface ";
            }

            $value = rtrim($value);

            $file->replace_lines("/^" . Firewall::ROLE_EXTERNAL . "=/i", Firewall::ROLE_EXTERNAL . "=\"$value\"\n");
        }

        if ($role != Firewall::ROLE_DMZ) {
            try {
                $value = $file->lookup_value("/^" . Firewall::ROLE_DMZ . "=/");
            } catch (File_No_Match_Exception $e) {
                throw new Firewall_Undefined_Role_Exception();
            }

            $value = preg_replace("/\"/", "", $value);
            $list = explode(" ", $value);
            $value = "";

            foreach ($list as $iface)
                if ($iface != $device) $value .= "$iface ";

            $value = rtrim($value);

            $file->replace_lines("/^" . Firewall::ROLE_DMZ . "=/i", Firewall::ROLE_DMZ . "=\"$value\"\n");
        }

        try {
            $value = $file->lookup_value("/^$role=/");
        } catch (File_No_Match_Exception $e) {
            $value = '';
            $file->add_lines_after("$role=\n", "/^LANIF/");
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        $value = preg_replace("/\"/", "", $value);
        $allifs = preg_split("/\s+/", $value);
        $allifs[] = $device;
        sort($allifs);
        $value = implode(" ", array_unique($allifs));
        $value = ltrim($value);

        $file->replace_lines("/^$role=/i", "$role=\"$value\"\n");
    }

    /**
     * Remove interface role.  The interface is removed from any role variables
     * if it has been previously assigned a role.
     *
     * @param string device Interface name
     *
     * @return void
     * @throws Engine_Exception, Firewall_Undefined_Role_Exception
     */

    public function remove_interface_role($device)
    {
        clearos_profile(__METHOD__, __LINE__);

        $remove[] = $device;
        $file = new File(Firewall::FILE_CONFIG);

        for ($i = 0; $i < 4; $i++) {
            switch ($i) {
            case 0:
            default:
                $role = Firewall::ROLE_LAN;
                break;
            case 1:
                $role = Firewall::ROLE_HOT_LAN;
                break;
            case 2:
                $role = Firewall::ROLE_EXTERNAL;
                break;
            case 3:
                $role = Firewall::ROLE_DMZ;
            }

            try {
                $value = $file->lookup_value("/^$role=/");
            } catch (File_No_Match_Exception $e) {
                throw new Firewall_Undefined_Role_Exception();
            }

            $value = trim(preg_replace("/\"/", "", $value));
            $value = implode(" ", array_diff(explode(" ", $value), $remove));

            $file->replace_lines("/^$role=/i", "$role=\"$value\"\n");
        }
    }

    /**
     * Get array of firewall rules.
     *
     *
     * @return array rules Firewall_Rule objects
     * @throws Engine_Exception
     */

    public function get_rules()
    {
        clearos_profile(__METHOD__, __LINE__);

        $rules = array();

        $file = new File(Firewall::FILE_CONFIG);
        $conf = $file->get_contents();

        $parts = array();
        
        if (eregi("RULES=\"([A-Z0-9|/_:.\\[:space:]-]*)\"", $conf, $parts) && strlen($parts[1])) {
            $value = trim(str_replace(array("\n", "\\", "\t"), " ", $parts[1]));
            while(strstr($value, "  ")) $value = str_replace("  ", " ", $value);

            if(!strlen($value)) return $rules;

            foreach(explode(" ", $value) as $rule)
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
     *
     * @return void
     * @throws Engine_Exception
     */

    public function set_rules($rules)
    {
        clearos_profile(__METHOD__, __LINE__);

        $buffer = "";
        sort($rules);

        foreach ($rules as $rule) {
            $value = "";
            $value = $rule->get_rule();

            $buffer .= sprintf("\t%s \\\n", $value);
        }

        $contents = NULL;
        $fw_conf = new File(Firewall::FILE_CONFIG);

        $contents = $fw_conf->get_contents();

        if (($conf = eregi_replace("RULES=\"[A-Z0-9|/_:.\\[:space:]-]*\"",
            "RULES=\"\\\n$buffer\"", $contents))) {

            $temp = new File("firewall", FALSE, TRUE);
            $temp->add_lines("$conf\n");

            $fw_conf->Replace($temp->get_filename());
        } else {
            throw new Engine_Exception(lang('firewall_firewall_configuration_is_invalid'));
        }
    }

    /**
     * Find firewall rule.
     *
     * @param object val Firewall_Rule object to search for
     *
     * @return object Matching rule
     */

    public function find_rule($val)
    {
        clearos_profile(__METHOD__, __LINE__);

        $rules = $this->get_rules();

        foreach ($rules as $rule)
            if ($val->is_equal($rule)) return $rule;

        return NULL;
    }

    /**
     * Add firewall rule.
     *
     * @param object val Firewall_Rule object to add
     *
     * @return void
     * @throws Engine_Exception
     */

    public function add_rule($val)
    {
        clearos_profile(__METHOD__, __LINE__);

        $val->get_rule();
        $rules = $this->get_rules();

        foreach($rules as $rule)
        {
            if ($val->is_equal($rule))
                throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
        }

        $rules[] = $val;

        $this->set_rules($rules);
    }

    /**
     * Delete firewall rule.
     *
     * @param object val Firewall_Rule object to delete
     *
     * @return void
     * @throws Engine_Exception
     */

    public function delete_rule($val)
    {
        clearos_profile(__METHOD__, __LINE__);

        $val->get_rule();
        $old_rules = $this->get_rules();

        $exists = FALSE;
        $new_rules = array();

        foreach ($old_rules as $rule) {
            if (!$val->is_equal($rule)) {
                $new_rules[] = $rule;
                continue;
            }

            $exists = TRUE;
        }

        if (!$exists)
            throw new Engine_Exception(lang('firewall_firewall_rule_not_found'));

        $this->set_rules($new_rules);
    }

    ///////////////////////////////////////////////////////////////////////////
    // G E N E R I C   M E T H O D S
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Generic add for host, IP or network list.
     *
     * @param string host domain name, IP, or network address
     * @param string key key for the list
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function add_host($host, $key)
    {
        clearos_profile(__METHOD__, __LINE__);


        // Validate
        //---------
/*
        // FIXME
        Validation_Exception::is_valid($this->validate_host($host));


        if (! $host)
            throw new Engine_Exception(lang('firewall_lang_host_is_invalid'))
*/

        // Grab the current list (if any)
        //-------------------------------

        try {
            $hostlist = $this->get_hosts($key);
        } catch (File_No_Match_Exception $e) {
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        if ($hostlist) {
            foreach ($hostlist as $hostinfo) {
                if ($hostinfo[host] == $host) {
                    throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
                }
                $thelist .= $hostinfo[host] . " ";
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
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        // If key does not exist, add it
        //------------------------------

        try {
            $file->add_lines("$key=\"$thelist\"\n");
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }
    }

    /**
     * Generic add for a protocol/port list.
     *
     * @param string protocol the protocol - UDP/TCP
     * @param string port service name, port number
     * @param string key key for the list
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function add_port($protocol, $port, $key)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($port));

        // Grab the current list (if any)
        //-------------------------------

        try {
            $portlist = $this->get_ports($key);
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        if ($portlist) {
            foreach ($portlist as $portinfo) {
                if (($portinfo[protocol] == $protocol) && ($portinfo[port] == $port)) {
                    throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
                }
                $thelist .= $portinfo[protocol] . "|" . $portinfo[port] . " ";
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
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        // If key does not exist, add it
        //------------------------------

        try {
            $file->add_lines("$key=\"$thelist\"\n");
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }
    }

    /**
     * Generic add for a protocol/port-range list.
     *
     * @param string protocol the protocol - UDP/TCP
     * @param string from from service name, port number
     * @param string to to service name, port number
     * @param string key key for the list
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function add_port_range($protocol, $from, $to, $key)
    {
        clearos_profile(__METHOD__, __LINE__);

        // Validate
        //---------

        if (! $this->IsValidProtocol($protocol)) {
            throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, COMMON_WARNING);
        }

        if (! $this->IsValidPortRange($from, $to)) {
            throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PORT_INVALID, COMMON_WARNING);
        }

        // Grab the current list (if any)
        //-------------------------------

        try {
            $portlist = $this->GetPortRanges($key);
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        if ($portlist) {
            foreach ($portlist as $portinfo) {
                if (($portinfo[protocol] == $protocol) && ($portinfo[from] == $from) && ($portinfo[to] == $to)) {
                    throw new Engine_Exception(FIREWALL_LANG_ERRMSG_RULE_EXISTS, COMMON_WARNING);
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
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        // If key does not exist, add it
        //------------------------------

        try {
            $file->add_lines("$key=\"$thelist\"\n");
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }
    }

    /**
     * Generic add for a protocol/port list - specified by service name.
     *
     * @param string service service name eg HTTP, FTP, SMTP
     * @param string key key for the list
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function add_standard_service($service, $key)
    {
        clearos_profile(__METHOD__, __LINE__);

        // Validate
        //---------

        if (! $this->IsValidService($service)) {
            throw new Engine_Exception(FIREWALL_LANG_ERRMSG_SERVICE_INVALID, COMMON_WARNING);
        }

        $myports = $this->ports;
        foreach ($myports as $portinfo) {
            if ($portinfo[3] == $service) {

                if ($portinfo[0] == Firewall::CONSTANT_NORMAL) {
                    try {
                        $this->AddPort($portinfo[1], $portinfo[2], $key);
                    } catch (Exception $e) {
                        throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
                    }    
                } else {
                    throw new Engine_Exception(LOCALE_LANG_ERRMSG_PARSE_ERROR, COMMON_WARNING);
                }
            }
        }
    }

    /**
     * Generic delete for a host/IP/network list.
     *
     * @param string host host, IP or network
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function delete_host($host, $key)
    {
        clearos_profile(__METHOD__, __LINE__);

        // Validate
        //---------

        if (! $host) {
            throw new Engine_Exception(FIREWALL_LANG_ERRMSG_HOST_INVALID, COMMON_WARNING);
        }

        // Grab the current list (if any)
        //-------------------------------

        try {
            $hostlist = $this->get_hosts($key);
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
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
            $match = $file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
        } catch (File_No_Match_Exception $e) {
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        // If key does not exist, add it
        //------------------------------

        try {
            $file->add_lines("$key=\"$thelist\"\n");
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }
    }

    /**
     * Generic delete for a protocol/port list.
     *
     * @param string protocol the protocol - UDP/TCP
     * @param string port service name, port number
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function delete_port($protocol, $port, $key)
    {
        clearos_profile(__METHOD__, __LINE__);

        // Validate
        //---------

        if (! $this->IsValidProtocol($protocol)) {
            throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, COMMON_WARNING);
        }

        if (! $this->IsValidPort($port)) {
            throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PORT_INVALID, COMMON_WARNING);
        }

        // Grab the current list (if any)
        //-------------------------------

        try {
            $portlist = $this->get_ports($key);
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
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
            $file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
        } catch (File_No_Match_Exception $e) {
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        // If key does not exist, add it
        //------------------------------

        try {
            $file->add_lines("$key=\"$thelist\"\n");
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }
    }

    /**
     * Generic delete for a protocol/port-range list.
     *
     * @param string protocol the protocol - UDP/TCP
     * @param string port service name, port number
     * @param string key key for the list
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function delete_port_range($protocol, $from, $to, $key)
    {
        clearos_profile(__METHOD__, __LINE__);

        // Validate
        //---------

        if (! $this->IsValidProtocol($protocol)) {
            throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PROTOCOL_INVALID, COMMON_WARNING);
        }

        if (! $this->IsValidPortRange($from, $to)) {
            throw new Engine_Exception(FIREWALL_LANG_ERRMSG_PORT_INVALID, COMMON_WARNING);
        }

        // Grab the current list (if any)
        //-------------------------------

        try {
            $portlist = $this->GetPortRanges($key);
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
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
            $file->replace_lines("/^$key=/i", "$key=\"$thelist\"\n");
        } catch (File_No_Match_Exception $e) {
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        // If key does not exist, add it
        //------------------------------

        try {
            $file->add_lines("$key=\"$thelist\"\n");
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }
    }

    /**
     * Generic get list for a hosts or networks.
     *
     * @param string key key for the list
     *
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
            return NULL;
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        // - Get rid of quotes
        // - Make multiple spaces one single space
        $rawline = preg_replace("/\"/", "", $rawline);
        $rawline = preg_replace("/ +/", " ", $rawline);

        if (!$rawline) return NULL;

        $hostlist = array();
        $hostinfo = array();
        $itemlist = array();

        $itemlist = explode(" ", $rawline);
        foreach ($itemlist as $host) {
            $hostinfo[host] = $host;
            try {
                $hostinfo[metainfo] = $this->LookupHostMetainfo($host);
            } catch (Exception $e) {
                throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
            }
            $hostlist[] = $hostinfo;
        }

        return $hostlist;
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
     *
     * @return array allowed incoming port ranges
     */

    protected function get_port_ranges($key)
    {
        clearos_profile(__METHOD__, __LINE__);

        $file = new File(Firewall::FILE_CONFIG);

        try {
            $rawline = $file->lookup_value("/^$key=/");
        } catch (File_No_Match_Exception $e) {
            return NULL;
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
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
     *
     * @return array allowed incoming ports
     */

    protected function get_ports($key)
    {
        clearos_profile(__METHOD__, __LINE__);

        $file = new File(Firewall::FILE_CONFIG);

        try {
            $rawline = $file->lookup_value("/^$key=/");
        } catch (File_No_Match_Exception $e) {
            return NULL;
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
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
                throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
            }

            $portlist[] = $portinfo;
        }

        return $portlist;
    }

    /**
     * Generic get state for a on/off key.
     *
     * @param string key key for the list
     *
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
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
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
     *
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
            return NULL;
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
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
     *
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
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }

        // If tag does not exist, add it
        //------------------------------

        try {
            $file->add_lines_after("$key=\"$interface\"\n", "/^[^#]/");
        } catch (Exception $e) {
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
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
            throw new Engine_Exception(LOCALE_LANG_ERRMSG_INVALID_TYPE, COMMON_WARNING);
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
            throw new Engine_Exception(clearos_exception_message($e), COMMON_WARNING);
        }
    }

    /**
     * Generic set for a miscelleanous value.
     *
     * @param string $value value of the key
     * @param string $key key name
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function set_value($value, $key)
    {
        clearos_profile(__METHOD__, __LINE__);

        $file = new File(Firewall::FILE_CONFIG);

        $match = $file->replace_lines("/^$key=/", "$key=\"$value\"\n");

        if (! $match)
            $file->add_lines_after("$key=\"$value\"\n", "/^[^#]/");
    }

    ///////////////////////////////////////////////////////////////////////////
    // V A L I D A T I O N   R O U T I N E S
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Validation routine for IPs
     *
     * @param string ip IP address
     *
     * @return boolean TRUE if IP address is valid
     */

    public function is_valid_ip($ip)
    {
        clearos_profile(__METHOD__, __LINE__);

        $parts = explode(".", $ip);

        if (sizeof($parts) != 4) return FALSE;

        foreach ($parts as $part) {
            if (!is_numeric($part) || ($part > 255) || ($part < 0))
                return FALSE;
        }

        return TRUE;
    }

    /**
     * Validation routine for firewall mode.
     *
     * @param string mode Firewall mode
     *
     * @return boolean TRUE if mode is valid
     */

    public function is_valid_mode($mode)
    {
        clearos_profile(__METHOD__, __LINE__);

        switch($mode) {
            case Firewall::MODE_GATEWAY:
            case Firewall::MODE_STANDALONE:
            case Firewall::MODE_TRUSTED_STANDALONE:
            case Firewall::MODE_TRUSTED_GATEWAY:
            return TRUE;
        }

        return FALSE;
    }

    /**
     * Validation routine for MACs
     *
     * @param string mac MAC address
     *
     * @return boolean TRUE if MAC address is valid
     */

    public function is_valid_mac($mac)
    {
        clearos_profile(__METHOD__, __LINE__);

        // sample: 00:02:2D:53:2B:84
        $parts = explode(":", $mac);

        if (sizeof($parts) != 6) return FALSE;

        foreach ($parts as $part) {
            if (strlen($part) != 2) return FALSE;
        }

        return TRUE;
    }

    /**
     * Validation routine for integer port address
     *
     * @param int port Numeric port address
     *
     * @return boolean TRUE if port is valid
     */

    public function validate_port($port)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! preg_match("/^\d+$/", $port))
            return lang('firewall_port_is_invalid');

        // TODO: DMZ uses 0 as a flag for "all"
        if (($port > 65535) || ($port < 0))
            return lang('firewall_port_is_invalid');
    }

    /**
     * Validation routine for integer port range
     *
     * @param int from Low port address
     * @param int to High port address
     *
     * @return boolean TRUE if port range is valid
     */

    public function validate_port_range($from, $to)
    {
        clearos_profile(__METHOD__, __LINE__);

        if ((! preg_match("/^\d+$/", $from)) || (! preg_match("/^\d+$/", $to)))
            return FALSE;

        if (($from > 65535) || ($from <= 0) || ($to > 65535) || ($to <= 0))
            return FALSE;

        if ($from > $to)
            return FALSE;

        return TRUE;
    }

    /**
     * Validation routine for protocol (TCP, UDP, ALL).
     *
     * @param string $protocol protocol
     *
     * @return string error message if protocol is invalid
     */

    public function validate_protocol($protocol)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! preg_match("/^(TCP|UDP|ALL)$/", $protocol)) 
            return lang('firewall_protocol_is_invalid');
    }

    /**
     * Validation routine for role.
     *
     * @param string $role role
     *
     * @return string error message if role is invalid
     */

    public function validate_role($role)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! array_key_exists($role, $this->roles))
            return lang('firewall_network_role_is_invalid');
    }

    /**
     * Validation routine for service.
     *
     * @param string service service eg HTTP
     *
     * @return boolean TRUE if service is valid
     */

    public function is_valid_service($service)
    {
        clearos_profile(__METHOD__, __LINE__);

        $servicelist = $this->GetStandardServiceList();
        foreach ($servicelist as $item) {
            if ($service == $item) return TRUE;
        }
        return FALSE;
    }

    /**
     * Validation routine for IPSec Server
     *
     * @param boolean ipsecserver IPSec server toggle setting (TRUE/FALSE)
     *
     * @return boolean TRUE if ipsecserver is valid
     */

    public function is_valid_server($ipsecserver)
    {
        clearos_profile(__METHOD__, __LINE__);

        return (is_bool($ipsecserver));
    }
}
