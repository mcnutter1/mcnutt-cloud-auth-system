<?php
require_once __DIR__.'/util.php';
// Load environment from .env first, then config pulls from env
load_dotenv(__DIR__.'/../config/.env');
$CONFIG = load_config(__DIR__.'/../config/config.php');
