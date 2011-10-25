<?php

/**
 * Firewall metadata class.
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

clearos_load_language('firewall');

///////////////////////////////////////////////////////////////////////////////
// D E P E N D E N C I E S
///////////////////////////////////////////////////////////////////////////////

// Classes
//--------

use \clearos\apps\base\Engine as Engine;
use \clearos\apps\network\Network_Utils as Network_Utils;

clearos_load_library('base/Engine');
clearos_load_library('network/Network_Utils');

// Exceptions
//-----------

use \clearos\apps\base\Validation_Exception as Validation_Exception;

clearos_load_library('base/Validation_Exception');

///////////////////////////////////////////////////////////////////////////////
// C L A S S
///////////////////////////////////////////////////////////////////////////////

/**
 * Firewall metadata class.
 *
 * @category   Apps
 * @package    Firewall
 * @subpackage Libraries
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2004-2011 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/firewall/
 */

class Metadata extends Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // V A R I A B L E S
    ///////////////////////////////////////////////////////////////////////////

    protected $ports = array();
    protected $domains = array();

    ///////////////////////////////////////////////////////////////////////////
    // M E T H O D S
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Firewall metadata constructor.
     */

    public function __construct()
    {
        clearos_profile(__METHOD__, __LINE__);

        include clearos_app_base('firewall') . '/deploy/ports.php';
        include clearos_app_base('firewall') . '/deploy/domains.php';

        $this->ports = $ports;
        $this->domains = $domains;
    }

    /**
     * Returns ports metadata.
     *
     * @return array list of ports metadata
     * @throws Engine_Exception
     */

    public function get_ports_list()
    {
        clearos_profile(__METHOD__, __LINE__);

        return $this->ports;
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
     * Checks service name.
     *
     * @param string $service service name
     *
     * @return boolean TRUE if service name is valid.
     */

    public static function is_valid_service($service)
    {
        clearos_profile(__METHOD__, __LINE__);

        $metadata = new Metadata();

        $services = $metadata->get_standard_service_list();

        if (in_array($service, $services))
            return TRUE;
        else
            return FALSE;
    }

    /**
     * Returns the service defined by the given port/protocol.
     *
     * The protocol can be in either string (TCP/UDP) or numberic 
     * (6,17) format.
     *
     * @param string  $protocol protocol
     * @param integer $port     port
     *
     * @return string service
     * @throws Engine_Exception, Validation_Exception
     */

    public function lookup_service($protocol, $port)
    {
        clearos_profile(__METHOD__, __LINE__);


        if ($port)
            Validation_Exception::is_valid($this->validate_port($port));

        $firewall = new Firewall();

        if (is_numeric($protocol)) {
            Validation_Exception::is_valid($firewall->validate_ip_protocol($protocol));
            $protocol_name = $firewall->convert_protocol_number($protocol);
            $protocol_number = -1;
        } else {
            Validation_Exception::is_valid($firewall->validate_protocol($protocol));
            $protocol_name = 'nil';
            $protocol_number = $firewall->convert_protocol_name($protocol);
        }

        foreach ($this->ports as $port_info) {
            if ((($port_info[1] == $protocol_number) || ($port_info[1] == $protocol_name)) && ($port_info[2] == $port))
                return $port_info[3];
        }
    }

    /**
     * Returns the special name for a given host (eg ICQ servers).
     *
     * @param string $hostname hostname
     *
     * @return string meta name
     * @throws Engine_Exception, Validation_Exception
     */

    public function lookup_host_metainfo($hostname)
    {
        // FIXME: change to lookup_hostname_metainfo

        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_hostname($hostname));

        foreach ($this->domains as $host_info) {
            if ($host_info[0] === $hostname)
                return $host_info[1];
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // V A L I D A T I O N   R O U T I N E S
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Validation routine for hostname.
     *
     * @param string $hostname hostname
     *
     * @return string error message if hostname is invalid
     */

    public function validate_hostname($hostname)
    {
        clearos_profile(__METHOD__, __LINE__);

        if (! Network_Utils::is_valid_hostname($hostname))
            return lang('firewall_hostname_invalid');
    }

    /**
     * Validation routine for port.
     *
     * @param integer $port port
     *
     * @return string error message if port is invalid
     */

    public function validate_port($port)
    {
        clearos_profile(__METHOD__, __LINE__);

        $firewall = new Firewall();

        return $firewall->validate_port($port);
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

        $firewall = new Firewall();

        return $firewall->validate_protocol($protocol);
    }
}
