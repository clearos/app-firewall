<?php

/////////////////////////////////////////////////////////////////////////////
// General information
/////////////////////////////////////////////////////////////////////////////

$app['basename'] = 'firewall';
$app['version'] = '2.2.7';
$app['release'] = '1';
$app['vendor'] = 'ClearFoundation';
$app['packager'] = 'ClearFoundation';
$app['license'] = 'GPLv3';
$app['license_core'] = 'LGPLv3';
$app['description'] = lang('firewall_app_description');

/////////////////////////////////////////////////////////////////////////////
// App name and categories
/////////////////////////////////////////////////////////////////////////////

$app['name'] = lang('firewall_app_name');
$app['category'] = lang('base_category_network');
$app['subcategory'] = lang('base_subcategory_firewall');
$app['menu_enabled'] = FALSE;

/////////////////////////////////////////////////////////////////////////////
// Packaging
/////////////////////////////////////////////////////////////////////////////

$app['requires'] = array(
    'app-network >= 1:2.1.13',
);

$app['core_obsoletes'] = array(
    'iptables-services',
);

$app['core_requires'] = array(
    'app-events-core',
    'app-network-core',
    'csplugin-filewatch',
    'firewall >= 1.4.21-7',
    'iptables',
    'csplugin-events',
);

$app['core_directory_manifest'] = array(
    '/var/clearos/firewall' => array(),
    '/etc/clearos/firewall.d' => array(),
    '/var/state/firewall' => array(),
);

$app['core_symlinks'] = array(
    '/usr/sbin/firewall-start' => '/usr/sbin/firewall-start6'
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
    'filewatch-firewall.conf' => array(
        'target' => '/etc/clearsync.d/filewatch-firewall.conf',
    ),
    'network-proxy-event'=> array(
        'target' => '/var/clearos/events/network_proxy/firewall',
        'mode' => '0755'
    ),
);
