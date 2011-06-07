<?php

/////////////////////////////////////////////////////////////////////////////
// General information
/////////////////////////////////////////////////////////////////////////////

$app['basename'] = 'firewall';
$app['version'] = '5.9.9.2';
$app['release'] = '1';
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
    'iptables',
);

$app['core_file_manifest'] = array(
   'firewall-up' => array(
        'target' => '/usr/sbin/firewall-up',
        'mode' => '0755',
        'owner' => 'root',
        'group' => 'root',
    ),
);
