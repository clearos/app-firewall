<?php

/**
 * Firewall role class.
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

use \clearos\apps\base\Engine as Engine;
use \clearos\apps\base\File as File;
use \clearos\apps\firewall\Firewall as Firewall;
use \clearos\apps\firewall\Role as Role;

clearos_load_library('base/Engine');
clearos_load_library('base/File');
clearos_load_library('firewall/Firewall');
clearos_load_library('firewall/Role');

// Exceptions
//-----------

use \clearos\apps\base\Engine_Exception as Engine_Exception;
use \clearos\apps\base\File_No_Match_Exception as File_No_Match_Exception;
use \clearos\apps\base\File_Not_Found_Exception as File_Not_Found_Exception;
use \clearos\apps\base\Validation_Exception as Validation_Exception;

clearos_load_library('base/Engine_Exception');
clearos_load_library('base/File_No_Match_Exception');
clearos_load_library('base/File_Not_Found_Exception');
clearos_load_library('base/Validation_Exception');

///////////////////////////////////////////////////////////////////////////////
// C L A S S
///////////////////////////////////////////////////////////////////////////////

/**
 * Firewall role class.
 *
 * @category   Apps
 * @package    Firewall
 * @subpackage Libraries
 * @author     ClearFoundation <developer@clearfoundation.com>
 * @copyright  2004-2011 ClearFoundation
 * @license    http://www.gnu.org/copyleft/lgpl.html GNU Lesser General Public License version 3 or later
 * @link       http://www.clearfoundation.com/docs/developer/apps/firewall/
 */

class Role extends Engine
{
    ///////////////////////////////////////////////////////////////////////////
    // C O N S T A N T S
    ///////////////////////////////////////////////////////////////////////////

    // Files and paths
    const FILE_CONFIG = '/etc/firewall';

    // Roles
    const ROLE_EXTERNAL = 'EXTIF';
    const ROLE_DMZ = 'DMZIF';
    const ROLE_LAN = 'LANIF';
    const ROLE_HOT_LAN = 'HOTIF';

    ///////////////////////////////////////////////////////////////////////////
    // V A R I A B L E S
    ///////////////////////////////////////////////////////////////////////////

    protected $roles = array();

    ///////////////////////////////////////////////////////////////////////////
    // M E T H O D S
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Firewall constructor.
     */

    public function __construct()
    {
        clearos_profile(__METHOD__, __LINE__);

        $this->roles = array(
            Role::ROLE_LAN => lang('firewall_lan'),
            Role::ROLE_HOT_LAN => lang('firewall_hot_lan'),
            Role::ROLE_EXTERNAL => lang('firewall_external'),
            Role::ROLE_DMZ => lang('firewall_dmz'),
        );
    }

    /**
     * Returns network interface definition.
     *
     * The firewall needs to know which interface performs which role.
     * If you pass the interface role into this method, it will return the
     * interface (eg eth0).  The interface roles are defined as follows:
     *
     *  Role::ROLE_EXTERNAL
     *  Role::ROLE_LAN
     *  Role::ROLE_HOT_LAN
     *  Role::ROLE_DMZ
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

        if ($role === Role::ROLE_LAN) {
            $key = Role::ROLE_LAN;
            $default = 'eth1';
        } else if ($role === Role::ROLE_HOT_LAN) {
            $key = Role::ROLE_HOT_LAN;
            $default = 'eth1';
        } else if ($role === Role::ROLE_EXTERNAL) {
            $key = Role::ROLE_EXTERNAL;
            // TODO: cleanup
            // If we see ppp0 defined, we assume it is either a DSL or dial-up
            // connection to the Internet.
            if (file_exists('/etc/sysconfig/network-scripts/ifcfg-ppp0'))
                $default = 'ppp0';
            else
                $default = 'eth0';
        } else if ($role === Role::ROLE_DMZ) {
            $key = Role::ROLE_DMZ;
            $default = '';
        }

        $file = new File(Firewall::FILE_CONFIG);

        try {
            $role = $file->lookup_value("/^$key=/");
        } catch (File_No_Match_Exception $e) {
            $role = '';
        } catch (File_Not_Found_Exception $e) {
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
     *  Role::ROLE_EXTERNAL
     *  Role::ROLE_HOT_LAN
     *  Role::ROLE_LAN
     *  Role::ROLE_DMZ
     *
     * @param string $device interface name
     *
     * @return string $interface network role
     * @throws Engine_Exception
     */

    public function get_interface_role($device)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_device($device));

        if (strpos($device, ":") === FALSE)
            $ifname = $device;
        else
            list($ifname, $unit) = preg_split('/:/', $device, 5);

        $iface = '';
        $key = Role::ROLE_DMZ;

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

        $key = Role::ROLE_EXTERNAL;

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

        $key = Role::ROLE_HOT_LAN;

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

        return Role::ROLE_LAN;
    }

    /**
     * Returns network interface role in text.
     *
     * @param string $device interface name
     *
     * @return string interface role
     * @throws Engine_Exception
     */

    public function get_interface_role_text($device)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_device($device));

        $role = $this->get_interface_role($device);

        return $this->roles[$role];
    }

    /**
     * Set network interface role.  The interface is first removed from it's
     * previous role (if any).
     *
     * @param string $device interface name
     * @param string $role   interface role
     *
     * @return void
     * @throws Engine_Exception
     */

    public function set_interface_role($device, $role)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_device($device));
        Validation_Exception::is_valid($this->validate_role($role));

        $file = new File(Firewall::FILE_CONFIG);

        if ($role != Role::ROLE_LAN) {
            try {
                $value = $file->lookup_value("/^" . Role::ROLE_LAN . "=/");
            } catch (File_Not_Found_Exception $e) {
            } catch (File_No_Match_Exception $e) {
            }

            if (! empty($value)) {
                $value = preg_replace("/\"/", "", $value);
                $list = explode(" ", $value);
                $value = "";

                foreach ($list as $iface)
                    if ($iface != $device) $value .= "$iface ";

                $value = rtrim($value);

                $file->replace_lines("/^" . Role::ROLE_LAN . "=/i", Role::ROLE_LAN . "=\"$value\"\n");
            }
        }

        if ($role != Role::ROLE_HOT_LAN) {
            try {
                $value = $file->lookup_value("/^" . Role::ROLE_HOT_LAN . "=/");
            } catch (File_Not_Found_Exception $e) {
            } catch (File_No_Match_Exception $e) {
            }

            if (! empty($value)) {
                $value = preg_replace("/\"/", "", $value);
                $list = explode(" ", $value);
                $value = "";

                foreach ($list as $iface)
                    if ($iface != $device) $value .= "$iface ";

                $value = rtrim($value);

                $file->replace_lines("/^" . Role::ROLE_HOT_LAN . "=/i", Role::ROLE_HOT_LAN . "=\"$value\"\n");
            }
        }

        if ($role != Role::ROLE_EXTERNAL) {
            try {
                $value = $file->lookup_value("/^" . Role::ROLE_EXTERNAL . "=/");
            } catch (File_Not_Found_Exception $e) {
            } catch (File_No_Match_Exception $e) {
            }

            if (! empty($value)) {
                $value = preg_replace("/\"/", "", $value);
                $list = explode(" ", $value);
                $value = "";

                foreach ($list as $iface)
                    if ($iface != $device) $value .= "$iface ";

                $value = rtrim($value);

                $file->replace_lines("/^" . Role::ROLE_EXTERNAL . "=/i", Role::ROLE_EXTERNAL . "=\"$value\"\n");
            }
        }

        if ($role != Role::ROLE_DMZ) {
            try {
                $value = $file->lookup_value("/^" . Role::ROLE_DMZ . "=/");
            } catch (File_Not_Found_Exception $e) {
            } catch (File_No_Match_Exception $e) {
            }

            if (! empty($value)) {
                $value = preg_replace("/\"/", "", $value);
                $list = explode(" ", $value);
                $value = "";

                foreach ($list as $iface)
                    if ($iface != $device) $value .= "$iface ";

                $value = rtrim($value);

                $file->replace_lines("/^" . Role::ROLE_DMZ . "=/i", Role::ROLE_DMZ . "=\"$value\"\n");
            }
        }

        try {
            if (! $file->exists())
                $file->create('root', 'root', '0644');

            $value = $file->lookup_value("/^$role=/");
        } catch (File_No_Match_Exception $e) {
            $value = '';
            $file->add_lines("$role=\n");
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
     * Removes interface role.
     *
     * The interface is removed from any role variables
     * if it has been previously assigned a role.
     *
     * @param string $device interface name
     *
     * @return void
     * @throws Engine_Exception
     */

    public function remove_interface_role($device)
    {
        clearos_profile(__METHOD__, __LINE__);

        Validation_Exception::is_valid($this->validate_device($device));

        $remove[] = $device;
        $file = new File(Firewall::FILE_CONFIG);

        for ($i = 0; $i < 4; $i++) {
            switch ($i) {
                case 0:
                default:
                    $role = Role::ROLE_LAN;
                    break;
                case 1:
                    $role = Role::ROLE_HOT_LAN;
                    break;
                case 2:
                    $role = Role::ROLE_EXTERNAL;
                    break;
                case 3:
                    $role = Role::ROLE_DMZ;
            }

            try {
                $value = $file->lookup_value("/^$role=/");
            } catch (File_No_Match_Exception $e) {
            }

            $value = trim(preg_replace("/\"/", "", $value));
            $value = implode(" ", array_diff(explode(" ", $value), $remove));

            $file->replace_lines("/^$role=/i", "$role=\"$value\"\n");
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // V A L I D A T I O N   R O U T I N E S
    ///////////////////////////////////////////////////////////////////////////

    /**
     * Validation routine for network device.
     *
     * @param string $device network device
     *
     * @return string error message if network device is invalid
     */

    public function validate_device($device)
    {
        clearos_profile(__METHOD__, __LINE__);

        // FIXME
        // return lang('firewall_network_device_is_invalid');
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
}
