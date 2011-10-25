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
use \clearos\apps\network\Network_Utils as Network_Utils;

clearos_load_library('base/Daemon');
clearos_load_library('base/File');
clearos_load_library('firewall/Firewall');
clearos_load_library('firewall/Metadata');
clearos_load_library('firewall/Rule');
clearos_load_library('network/Network_Utils');

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
    const FILE_CONFIG = '/etc/clearos/firewall.conf';

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
    const PROTOCOL_IP = 0;
    const PROTOCOL_TCP = 6;
    const PROTOCOL_UDP = 17;
    const PROTOCOL_GRE = 47;
    const PROTOCOL_ESP = 50;
    const PROTOCOL_AH = 51;

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
    const PROTOCOL_ALL = 'ALL';
    const CONSTANT_MULTIPATH = 'MULTIPATH';

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
     * Returns the pre-defined list of IP protocols.
     *
     * @return array list of pre-defined IP protocols
     * @throws Engine_Exception
     */

    public function get_basic_protocols()
    {
        clearos_profile(__METHOD__, __LINE__);

        $protocols = array(
            self::PROTOCOL_TCP => 'TCP',
            self::PROTOCOL_UDP => 'UDP',
        );

        return $protocols;
    }

    /**
     * Returns protocol list.
     *
     * @return array list of protocols
     * @throws Engine_Exception
     */

    public function get_protocols()
    {
        clearos_profile(__METHOD__, __LINE__);

        $protocols = array(
            self::PROTOCOL_IP => 'IP',
            self::PROTOCOL_TCP => 'TCP',
            self::PROTOCOL_UDP => 'UDP',
            self::PROTOCOL_GRE => 'UDP',
            self::PROTOCOL_ESP => 'UDP',
            self::PROTOCOL_AH => 'AH',
        );

        return $protocols;
    }

    /**
     * Returns the pre-defined list of ports/and services.
     *
     * @return array list of pre-defined ports
     * @throws Engine_Exception
     */

    public function get_standard_service_list()
    {
        clearos_profile(__METHOD__, __LINE__);

        $metadata = new Metadata();
        
        return $metadata->get_standard_service_list();
    }

    /**
     * Returns protocol name for given protocol number.
     *
     * @param string $protocol protocol name
     *
     * @return flag protocol flag
     */

    public function convert_protocol_name($protocol)
    {
        clearos_profile(__METHOD__, __LINE__);

        switch ($protocol) {

            case 'TCP':
                $protocol_number = Firewall::PROTOCOL_TCP;
                break;

            case 'UDP':
                $protocol_number = Firewall::PROTOCOL_UDP;
                break;

            case 'GRE':
                $protocol_number = Firewall::PROTOCOL_GRE;
                break;

            case 'ESP':
            case 'ipv6-crypt':
                $protocol_number = Firewall::PROTOCOL_ESP;
                break;

            case 'AH':
            case 'ipv6-auth':
                $protocol_number = Firewall::PROTOCOL_AH;
                break;

            case 'ALL':
                $protocol_number = Firewall::PROTOCOL_ALL;
                break;
        }

        return $protocol_number;
    }

    /**
     * Returns protocol number for a given name.
     *
     * @param string $protocol protocol number
     *
     * @return protocol number
     */

    public function convert_protocol_number($protocol)
    {
        clearos_profile(__METHOD__, __LINE__);

        switch ($protocol) {

            case Firewall::PROTOCOL_TCP:
                $protocol_number = 'TCP';
                break;

            case Firewall::PROTOCOL_UDP:
                $protocol_number = 'UDP';
                break;

            case Firewall::PROTOCOL_GRE:
                $protocol_number = 'GRE';
                break;

            case Firewall::PROTOCOL_ESP:
                $protocol_number = 'ESP';
                break;

            case Firewall::PROTOCOL_AH:
                $protocol_number = 'AH';
                break;

            case Firewall::PROTOCOL_ALL:
                $protocol_number = 'ALL';
                break;
        }

        return $protocol_number;
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
            throw new Engine_Exception(lang('firewall_rule_not_found'));

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

        foreach ($rules as $rule) {
            if ($val->is_equal($rule))
                return $rule;
        }

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

            while (strstr($value, '  '))
                $value = str_replace('  ', ' ', $value);

            if (!strlen($value))
                return $rules;

            foreach (explode(" ", $value) as $rule) {
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
            throw new Engine_Exception(lang('firewall_configuration_invalid'));
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
     * @param string $address address
     *
     * @return error message if address is invalid
     */

    public function validate_address($address)
    {
        clearos_profile(__METHOD__, __LINE__, "$address");

        // TODO: MAC addresses are passed in here (?)
        if (Network_Utils::is_valid_mac($address))
            return;

        $parts = array();

        // TODO: IPv6...

        if ( ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", $address, $parts) &&
            ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255)) return;
        else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,3})$", $address, $parts) &&
            ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 && $parts[5] < 32 && $parts[5] >= 8)) return;
        else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$",
            $address, $parts) && ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 &&
            $parts[5] <= 255 && $parts[6] <= 255 && $parts[7] <= 255 && $parts[8] <= 255)) return;
        else if (ereg("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3}):([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$",
            $address, $parts) && ($parts[1] <= 255 && $parts[2] <= 255 && $parts[3] <= 255 && $parts[4] <= 255 &&
            $parts[5] <= 255 && $parts[6] <= 255 && $parts[7] <= 255 && $parts[8] <= 255))
        {
            list($lo, $hi) = explode(":", $address);
            if (ip2long($lo) < ip2long($hi)) return;
        }
        else if (eregi("^[A-Z0-9.-]*$", $address)) return;

        return lang('firewall_address_invalid');
    }

    /**
     * Validation routine for IPs
     *
     * @param string ip IP address
     *
     * @return error message if IP is invalid
     */

    public function validate_ip($ip)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! Network_Utils::is_valid_ip($ip))
            return lang('firewall_ip_address_invalid');
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
     * Validation routine for network interface name.
     *
     * @param string $name network interface name.
     *
     * @return string error message if network interface name is invalid
     */

    public function validate_interface($interface)
    {
        clearos_profile(__METHOD__, __LINE__);

        // FIXME
        // if (! preg_match('/^[a-zA-Z0-9_\-\.]*$/', $interface))
        //    return lang('firewall_network_interface_invalid');
    }

    /**
     * Validation routine for IP protocols (TCP, UDP, GRE, ALL).
     *
     * @param string $protocol protocol
     *
     * @return string error message if protocol is invalid
     */

    public function validate_ip_protocol($protocol)
    {
        clearos_profile(__METHOD__, __LINE__);

        switch ($protocol) {
            case Firewall::PROTOCOL_TCP:
            case Firewall::PROTOCOL_UDP:
            case Firewall::PROTOCOL_GRE:
            case Firewall::PROTOCOL_ESP:
            case Firewall::PROTOCOL_AH:
            case Firewall::PROTOCOL_IP:
            case Firewall::PROTOCOL_ALL:
                return;
        }

        return lang('firewall_protocol_invalid');
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
            return lang('firewall_name_invalid');
    }

    /**
     * Validation routine for integer port address.
     *
     * @param int port Numeric port address
     *
     * @return boolean TRUE if port is valid
     */

    public function validate_port($port)
    {
        clearos_profile(__METHOD__, __LINE__);

        // TODO - Messy.
        // This method has been used to validate ports and port ranges.

        if ($port === Firewall::CONSTANT_ALL_PORTS)
            return;

        $ports = preg_split('/:/', $port, 2);

        foreach ($ports as $port) {
            if (! preg_match("/^\d+$/", $port))
                return lang('firewall_port_invalid');

            if (($port > 65535) || ($port < 0))
                return lang('firewall_port_is_out_of_range');
        }

        if (count($ports) >= 2) {
            if ($ports[0] > $ports[1])
                return lang('firewall_port_range_invalid');
        }
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

        // TODO: see validate_port TODO and clean up
        return $this->validate_port("$from:$to");
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

        switch ($protocol) {
            case 'TCP':
            case 'UDP':
                return;
        }

        return lang('firewall_protocol_invalid');
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
            return lang('firewall_standard_service_invalid');
    }
}
