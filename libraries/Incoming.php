<?php

/**
 * Firewall incoming class.
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

use \clearos\apps\firewall\Firewall as Firewall;
use \clearos\apps\firewall\Rule as Rule;

clearos_load_library('firewall/Firewall');
clearos_load_library('firewall/Rule');

// Exceptions
//-----------

use \clearos\apps\base\Engine_Exception as Engine_Exception;
use \clearos\apps\base\Validation_Exception as Validation_Exception;

clearos_load_library('base/Engine_Exception');
clearos_load_library('base/Validation_Exception');

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

class Incoming extends Firewall
{
    ///////////////////////////////////////////////////////////////////////////
    // M E T H O D S
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Incoming constructor.
     */

    public function __construct()
    {
        clearos_profile(__METHOD__, __LINE__);
    }

    /**
     * Adds a port/to the incoming allow list.
     *
     * @param string  $name     name
     * @param string  $protocol protocol
     * @param integer $port     port number
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function add_allow_port($name, $protocol, $port)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_name($name));
        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($port));

        switch ($protocol) {

            case 'TCP':
                $protocol_flag = Rule::PROTO_TCP;
                break;

            case 'UDP':
                $protocol_flag = Rule::PROTO_UDP;
                break;
        }

        $rule = new Rule();

        $rule->set_name($name);
        $rule->set_protocol($protocol_flag);
        $rule->set_port($port);
        $rule->set_flags(Rule::INCOMING_ALLOW | Rule::ENABLED);

        $this->add_rule($rule);
    }

    /**
     * Adds a port range to the incoming allow list.
     *
     * @param string  $name     name
     * @param string  $protocol protocol
     * @param integer $from     from port number
     * @param integer $to       to port number
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function add_allow_port_range($name, $protocol, $from, $to)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_name($name));
        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($from));
        Validation_Exception::is_valid($this->validate_port($to));

        switch ($protocol) {
            case 'TCP':
                $protocol_flag = Rule::PROTO_TCP;
                break;

            case 'UDP':
                $protocol_flag = Rule::PROTO_UDP;
                break;
        }

        $rule = new Rule();

        $rule->set_name($name);
        $rule->set_protocol($protocol_flag);
        $rule->set_port_range($from, $to);
        $rule->set_flags(Rule::INCOMING_ALLOW | Rule::ENABLED);

        $this->add_rule($rule);
    }

    /**
     * Adds a standard service to the incoming allow list.
     *
     * @param string $service service name eg HTTP, FTP, SMTP
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function add_allow_standard_service($service)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_service($service));

        if ($service == 'PPTP') {
            $this->set_pptp_server_state(TRUE);
        } else if ($service == 'IPsec') {
            $this->set_ipsec_server_state(TRUE);
        } else {
            $rule = new Rule();

            $ports = $this->get_ports_list();

            foreach ($ports as $port) {
                if ($port[3] != $service)
                    continue;

                // Replace / and space with underscore
                $rule->set_name(preg_replace('/[\/ ]/', '_', $service));
                $rule->set_protocol($rule->convert_protocol_name($port[1]));
                $rule->set_flags(Rule::INCOMING_ALLOW | Rule::ENABLED);

                if ($port[0] == Firewall::CONSTANT_PORT_RANGE) {
                    list($from, $to) = preg_split('/:/', $port[2], 2);
                    $rule->set_port_range($from, $to);
                } else {
                    $rule->set_port($port[2]);
                }

                $this->add_rule($rule);
            }
        }
    }

    /**
     * Block incoming host connection(s).
     *
     * @param string $name    rule nickname
     * @param string $address address
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function add_block_host($name, $address)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_name($name));
        Validation_Exception::is_valid($this->validate_address($address));

        $rule = new Rule();

        $rule->set_flags(Rule::INCOMING_BLOCK | Rule::ENABLED);
        $rule->set_address($address);
        $rule->set_name($name);

        $this->add_rule($rule);
    }

    /**
     * Checks to see if given port is open.
     *
     * The return value is one of the following:
     * - Firewall::CONSTANT_NOT_CONFIGURED
     * - Firewall::CONSTANT_ENABLED
     * - Firewall::CONSTANT_DISABLED
     *
     * @param string  $protocol protocol
     * @param integer $port     port number
     *
     * @return integer one of the described return values
     * @throws Engine_Exception, Validation_Exception
     */

    public function check_port($protocol, $port)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($port));

        $ports = $this->get_allow_ports();

        foreach ($ports as $portinfo) {
            if (($portinfo['port'] == $port) && ($portinfo['protocol'] == $protocol)) {
                if ($portinfo['enabled'])
                    return Firewall::CONSTANT_ENABLED;
                else
                    return Firewall::CONSTANT_DISABLED;
            }
        }

        return Firewall::CONSTANT_NOT_CONFIGURED;
    }

    /**
     * Delete a port from the incoming allow list.
     *
     * @param string  $protocol protocol
     * @param integer $port     port number
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function delete_allow_port($protocol, $port)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($port));

        $rule = new Rule();

        $rule->set_protocol($rule->convert_protocol_name($protocol));
        $rule->set_port($port);
        $rule->set_flags(Rule::INCOMING_ALLOW);

        $this->delete_rule($rule);
    }

    /**
     * Deletes a port range from the incoming allow list.
     *
     * @param string  $protocol protocol
     * @param integer $from     from port number
     * @param integer $to       to port number
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function delete_allow_port_range($protocol, $from, $to)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($from));
        Validation_Exception::is_valid($this->validate_port($to));

        $rule = new Rule();

        $rule->set_protocol($rule->convert_protocol_name($protocol));
        $rule->set_port_range($from, $to);
        $rule->set_flags(Rule::INCOMING_ALLOW);

        $this->delete_rule($rule);
    }

    /**
     * Delete incoming host block rule.
     *
     * @param string $address address
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function delete_block_host($address)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_address($address));

        $rule = new Rule();

        $rule->set_flags(Rule::INCOMING_BLOCK);
        $rule->set_address($address);

        $this->delete_rule($rule);
    }

    /**
     * Returns allowed incoming port ranges.
     *
     * The information is an array with the following hash array entries:
     *
     *  info[name]
     *  info[protocol]
     *  info[from]
     *  info[to]
     *  info[enabled]
     *
     * @return array array containing allowed incoming port ranges
     * @throws Engine_Exception
     */

    public function get_allow_port_ranges()
    {
        clearos_profile(__METHOD__, __LINE__);

        $port_list = array();

        $rules = $this->get_rules();

        foreach ($rules as $rule) {
            if (!strstr($rule->get_port(), ':'))
                continue;

            if (!($rule->get_flags() & Rule::INCOMING_ALLOW))
                continue;

            if ($rule->get_flags() & (Rule::WIFI | Rule::CUSTOM))
                continue;

            if (($rule->get_protocol() != Rule::PROTO_TCP) && ($rule->get_protocol() != Rule::PROTO_UDP))
                continue;

            $info = array();

            switch ($rule->get_protocol()) {
                case Rule::PROTO_TCP:
                    $info['protocol'] = 'TCP';
                    break;

                case Rule::PROTO_UDP:
                    $info['protocol'] = 'UDP';
                    break;
            }

            $info['name'] = $rule->get_name();
            $info['enabled'] = $rule->is_enabled();
            list($info['from'], $info['to']) = preg_split('/:/', $rule->get_port(), 2);
            $info['service'] = $this->lookup_service($info['protocol'], $info['from']);

            $port_list[] = $info;
        }

        return $port_list;
    }

    /**
     * Returns allowed incoming ports.
     *
     * The information is an array with the following hash array entries:
     *
     *  info[name]
     *  info[protocol]
     *  info[port]
     *  info[service] (FTP, HTTP, etc.)
     *
     * @return array array containing allowed incoming ports
     * @throws Engine_Exception
     */

    public function get_allow_ports()
    {
        clearos_profile(__METHOD__, __LINE__);

        $port_list = array();

            $rules = $this->get_rules();

        foreach ($rules as $rule) {
            if (strstr($rule->get_port(), ':'))
                continue;

            if (!($rule->get_flags() & Rule::INCOMING_ALLOW))
                continue;

            if ($rule->get_flags() & (Rule::WIFI | Rule::CUSTOM))
                continue;

            if (($rule->get_protocol() != Rule::PROTO_TCP) && ($rule->get_protocol() != Rule::PROTO_UDP))
                continue;

            $info = array();

            switch ($rule->get_protocol()) {
                case Rule::PROTO_TCP:
                    $info['protocol'] = 'TCP';
                    break;

                case Rule::PROTO_UDP:
                    $info['protocol'] = 'UDP';
                    break;
            }

            $info['name'] = $rule->get_name();
            $info['port'] = $rule->get_port();
            $info['enabled'] = $rule->is_enabled();
            $info['service'] = $this->lookup_service($info['protocol'], $info['port']);

            $port_list[] = $info;
        }

        return $port_list;
    }

    /**
     * Gets incoming host block rules.  The information is an array
     * with the following hash array entries:
     *
     *  info[name]
     *  info[host]
     *  info[enabled]
     *
     * @return array array containing incoming host block rules
     * @throws Engine_Exception
     */

    public function get_block_hosts()
    {
        clearos_profile(__METHOD__, __LINE__);

        $hosts = array();

        $rules = $this->get_rules();

        foreach ($rules as $rule) {
            if (!($rule->get_flags() & Rule::INCOMING_BLOCK))
                continue;

            if ($rule->get_flags() & Rule::CUSTOM)
                continue;

            $info = array();
            $info['name'] = $rule->get_name();
            $info['host'] = $rule->get_address();
            $info['enabled'] = $rule->is_enabled();

            $hosts[] = $info;
        }

        return $hosts;
    }

    /**
     * Returns IPSec server rule state.
     *
     * @return boolean TRUE if firewall allows incoming IPSec traffic
     * @throws Engine_Exception
     */

    public function get_ipsec_server_state()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->get_state('IPSEC_SERVER');
    }

    /**
     * Returns PPTP server rule state.
     *
     * @return boolean TRUE if firewall allows incoming PPTP traffic
     * @throws Engine_Exception
     */

    public function get_pptp_server_state()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->get_state('PPTP_SERVER');
    }

    /**
     * Sets IPSec server rule.
     *
     * @param boolean $state state of the special IPsec rule
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_ipsec_server_state($state)
    {
        clearos_profile(__METHOD__, __LINE__);

        $this->set_state($state, 'IPSEC_SERVER');
    }

    /**
     * Sets PPTP server rule.
     *
     * @param boolean $state state of the special PPTP server rule
     *
     * @return void
     * @throws Engine_Exception, Validation_Exception
     */

    public function set_pptp_server_state($state)
    {
        clearos_profile(__METHOD__, __LINE__);

        $this->set_state($state, 'PPTP_SERVER');
    }

    /**
     * Enable/disable a port from the incoming allow list.
     *
     * @param boolean $enabled  state of rule
     * @param string  $protocol protocol
     * @param integer $port     port number
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function toggle_enable_allow_port($enabled, $protocol, $port)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($port));

        $rule = new Rule();

        $rule->set_protocol($rule->convert_protocol_name($protocol));
        $rule->set_port($port);
        $rule->set_flags(Rule::INCOMING_ALLOW);

        if (!($rule = $this->find_rule($rule)))
            return;

        $this->delete_rule($rule);

        if ($enabled)
            $rule->enable();
        else
            $rule->disable();

        $this->add_rule($rule);
    }

    /**
     * Enable/disable a port range from the incoming allow list.
     *
     * @param boolean $enabled  state of rule
     * @param string  $protocol protocol
     * @param integer $from     from port number
     * @param integer $to       to port number
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function toggle_enable_allow_port_range($enabled, $protocol, $from, $to)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_protocol($protocol));
        Validation_Exception::is_valid($this->validate_port($from));
        Validation_Exception::is_valid($this->validate_port($to));

        $rule = new Rule();

        $rule->set_protocol($rule->convert_protocol_name($protocol));
        $rule->set_port_range($from, $to);
        $rule->set_flags(Rule::INCOMING_ALLOW);

        if (!($rule = $this->find_rule($rule)))
            return;

        $this->delete_rule($rule);

        if ($enabled)
            $rule->enable();
        else
            $rule->disable();

        $this->add_rule($rule);
    }

    /**
     * Enable/disable incoming host block rule.
     *
     * @param boolean $enabled state
     * @param string  $address address
     *
     * @return void
     * @throws Engine_Exception, ValidationException
     */

    public function toggle_enable_block_host($enabled, $address)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_address($address));

        $rule = new Rule();

        $rule->set_flags(Rule::INCOMING_BLOCK);
        $rule->set_address($address);

        if (!($rule = $this->find_rule($rule)))
            return;

        $this->delete_rule($rule);

        if ($enabled)
            $rule->enable();
        else
            $rule->disable();

        $this->add_rule($rule);
    }
}
