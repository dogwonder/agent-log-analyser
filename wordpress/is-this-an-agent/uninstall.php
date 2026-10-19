<?php

declare(strict_types=1);

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

function itia_remove_site_data(): void
{
    global $wpdb;
    $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}itia_daily");
    foreach (['itia_settings', 'itia_schema', 'itia_last_cleanup'] as $option) {
        delete_option($option);
    }
    wp_clear_scheduled_hook('itia_cleanup');
}

if (is_multisite()) {
    $offset = 0;
    do {
        $siteIds = get_sites(['fields' => 'ids', 'number' => 100, 'offset' => $offset]);
        foreach ($siteIds as $siteId) {
            switch_to_blog((int) $siteId);
            itia_remove_site_data();
            restore_current_blog();
        }
        $offset += 100;
    } while (count($siteIds) === 100);
} else {
    itia_remove_site_data();
}
