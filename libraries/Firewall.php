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
use \clearos\apps\firewall\Metadata as Metadata;
use \clearos\apps\firewall\Rule as Rule;

clearos_load_library('base/Daemon');
clearos_load_library('base/File');
clearos_load_library('firewall/Firewall');
clearos_load_library('firewall/Metadata');
clearos_load_library('firewall/Rule');

// Exceptions
//-----------

use \clearos\apps\base\Engine_Exception as Engine_Exception;
use \clearos\apps\base\File_No_Match_Exception as File_No_Match_Exception;
use \clearos\apps\firewall\Firewall_Invalid_Rule_Exception as Firewall_Invalid_Rule_Exception;
use \clearos\apps\firewall\Rule_Already_Exists_Exception as Rule_Already_Exists_Exception;

clearos_load_library('base/Engine_Exception');
clearos_load_library('base/File_No_Match_Exception');
clearos_load_library('firewall/Firewall_Invalid_Rule_Exception');
clearos_load_library('firewall/Rule_Already_Exists_Exception');

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

    // Status
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
     * Adds firewall rule.
     *
     * @param object $val Rule object
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function add_rule($val)
    {
        clearos_profile(__METHOD__, __LINE__);

        $val->get_rule();
        $rules = $this->get_rules();

        foreach($rules as $rule)
        {
            if ($val->is_equal($rule))
                throw new Rule_Already_Exists_Exception();
        }

        $rules[] = $val;

        $this->set_rules($rules);
    }

    /**
     * Deletes firewall rule.
     *
     * @param object $val Rule object
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function delete_rule($val)
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

    /**
     * Finds firewall rule.
     *
     * @param object $val Rule object
     *
     * @return object firewall rule
     */

    protected function find_rule($val)
    {
        clearos_profile(__METHOD__, __LINE__);

        $rules = $this->get_rules();

        foreach ($rules as $rule)
            if ($val->is_equal($rule)) return $rule;

        return NULL;
    }

    /**
     * Returns the ports list.
     *
     * @return array list of pre-defined ports
     * @throws Engine_Exception
     */

    protected function get_ports_list()
    {
        clearos_profile(__METHOD__, __LINE__);

        $metadata = new Metadata();
        
        return $metadata->get_ports_list();
    }

    /**
     * Get array of firewall rules.
     *
     *
     * @return array rules Rule objects
     * @throws Engine_Exception
     */

    protected function get_rules()
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
                $fwr = new Rule();

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
     * Returns the pre-defined list of ports/and services.
     *
     * @return array list of pre-defined ports
     * @throws Engine_Exception
     */

    protected function get_standard_service_list()
    {
        clearos_profile(__METHOD__, __LINE__);

        $metadata = new Metadata();
        
        return $metadata->get_standard_service_list();
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
        } else if ($retval == Firewall::CONSTANT_ON)
            return TRUE;

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
     * Returns the service defined by the given port/protocol.
     *
     * @param string  $protocol protocol
     * @param integer $port     port
     *
     * @return string service
     * @throws Engine_Exception, Validation_Exception
     */

    protected function lookup_service($protocol, $port)
    {
        clearos_profile(__METHOD__, __LINE__);

        $metadata = new Metadata();
        
        return $metadata->lookup_service($protocol, $port);
    }

    /**
     * Set firewall rules from array.
     *
     * @param array array of Rule objects
     *
     * @return void
     * @throws Engine_Exception
     */

    protected function set_rules($rules)
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
/// FIXME

/*
        if (! is_bool($state)) {
            throw new Engine_Exception(LOCALE_LANG_ERRMSG_INVALID_TYPE, COMMON_WARNING);
        }
*/

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
     * Validates address.
     *
     * Is this (hostname, IPv4, and soon IPv6) address valid?
     * localhost || 192.168.0.1 || 192.168.0.1/24 || 192.168.0.1/255.255.255.0 || 192.168.0.1:192.168.1.1
     *
     * TODO: hostname validation should be moved to IsValidHostname
     * TODO: network validation should be moved to IsValidNetwork
     * TODO: this class should extend Network() and use the standard validation
     *
     * @param string $ip hostname, IPv4 address to validate
     *
     * @return error message if address is invalid
     */

    public function validate_address($ip)
    {
        clearos_profile(__METHOD__, __LINE__);

        $parts = array();

        // TODO: IPv6...

        if ( ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", $ip, $parts) &&
            ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255)) return TRUE;
        else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,3})$", $ip, $parts) &&
            ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 && $parts[5] < 32 && $parts[5] >= 8)) return TRUE;
        else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$",
            $ip, $parts) && ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 &&
            $parts[5] <= 255 && $parts[6] <= 255 && $parts[7] <= 255 && $parts[8] <= 255)) return TRUE;
        else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$",
            $ip, $parts) && ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 &&
            $parts[5] <= 255 && $parts[6] <= 255 && $parts[7] <= 255 && $parts[8] <= 255))
        {
            list($lo, $hi) = explode(":", $ip);
            if (ip2long($lo) < ip2long($hi)) return TRUE;
        }
        else if (eregi("^[A-Z0-9.-]*$", $ip)) return TRUE;

        return lang('firewall_address_is_invalid');
    }

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
     * Validation routine for firewall rule name.
     *
     * @param string $name firewall rule name.
     *
     * @return string error message if firewall rule name is invalid
     */

    public function validate_name($name)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! preg_match('/^[a-zA-Z0-9_\-\.]*$/', $name))
            return lang('firewall_name_is_invalid');
    }

    /**
     * Validation routine for integer port range
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

        if (! preg_match('/^(TCP|UDP|ALL)$/', $protocol)) 
            return lang('firewall_protocol_is_invalid');
    }

    /**
     * Validation routine for service.
     *
     * @param string $service service eg HTTP
     *
     * @return error message if service is invalid
     */

    public function validate_service($service)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! Metadata::is_valid_service($service))
            return lang('firewall_standard_service_is_invalid');
    }
}
