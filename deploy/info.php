<?php

/////////////////////////////////////////////////////////////////////////////
// General information
/////////////////////////////////////////////////////////////////////////////

$app['basename'] = 'firewall';
$app['version'] = '5.9.9.2';
$app['release'] = '3.1';
$app['vendor'] = 'ClearFoundation';
$app['packager'] = 'ClearFoundation';
$app['license'] = 'GPLv3';
$app['license_core'] = 'LGPLv3';
$app['summary'] = lang('firewall_app_summary');
$app['description'] = lang('firewall_app_long_description');

/////////////////////////////////////////////////////////////////////////////
// App name and categories
/////////////////////////////////////////////////////////////////////////////

$app['name'] = lang('firewall_firewall');
$app['category'] = lang('base_category_network');
$app['subcategory'] = lang('base_subcategory_firewall');
$app['menu_enabled'] = FALSE;

/////////////////////////////////////////////////////////////////////////////
// Packaging
/////////////////////////////////////////////////////////////////////////////

$app['core_only'] = TRUE;

$app['requires'] = array(
    'app-network',
);

$app['core_requires'] = array(
    'app-network-core',
    'firewall',
    'iptables',
);

$app['core_directory_manifest'] = array(
   '/var/clearos/firewall' => array(),
   '/etc/clearos/firewall.d' => array(),
);

$app['core_file_manifest'] = array(
   'local' => array(
        'target' => '/etc/clearos/firewall.d/local',
        'mode' => '0755',
        'owner' => 'root',
        'group' => 'root',
        'config' => TRUE,
        'config_params' => 'noreplace',
    ),
   'firewall.conf' => array(
        'target' => '/etc/clearos/firewall.conf',
        'mode' => '0644',
        'owner' => 'root',
        'group' => 'root',
        'config' => TRUE,
        'config_params' => 'noreplace',
    ),
   'firewall.init' => array(
        'target' => '/etc/rc.d/init.d/firewall',
        'mode' => '0755',
        'owner' => 'root',
        'group' => 'root',
    ),
   'firewall-start' => array(
        'target' => '/usr/sbin/firewall-start',
        'mode' => '0755',
        'owner' => 'root',
        'group' => 'root',
    ),
   'types' => array(
        'target' => '/etc/clearos/firewall.d/types',
        'mode' => '0755',
        'owner' => 'root',
        'group' => 'root',
    ),
);
