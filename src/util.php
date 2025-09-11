<?php
function load_config($path){
  $_ENV = array_merge($_ENV, getenv());
  return include $path;
}
