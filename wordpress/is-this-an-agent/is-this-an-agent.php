<?php
/**
 * Plugin Name: Is this an agent?
 * Description: A small, mildly suspicious field guide to possible AI visitors. Clues, not convictions. Deactivating deletes its counts.
 * Version: 0.1.5
 * Requires at least: 6.5
 * Requires PHP: 8.2
 * Author: The Chancery Lane Project
 * License: GPL-2.0-or-later
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/includes/Detector.php';
require_once __DIR__ . '/includes/Repository.php';
require_once __DIR__ . '/includes/Plugin.php';

register_activation_hook(__FILE__, [\ChanceryLane\AgentFinder\Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [\ChanceryLane\AgentFinder\Plugin::class, 'deactivate']);
(new \ChanceryLane\AgentFinder\Plugin(__FILE__))->boot();
