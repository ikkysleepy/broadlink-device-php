<?php
include("include/broadlink.php");

$data = '260032017139100d0f2a0f0e0f0d0f0e0f0e0e0e0f0e0e0e0f0e0f0e0e0e0f0e0e2b0f0e0e0e0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f2b0f0d0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f2b0f0d0f2a102a0f2a0f2a0f0e0e0e0f2a100d0e2b0f2a1029102a0f0d0f2a1000099572390f0e0e2b0f0e0f0d0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f0e0e0f0f2a0e0e0f0e0f0e0e0e0f0e0f0d0f0e0e0f0e0e0f2a100d0e0f0e0e0f0e0e0e100d0e0f0e0e0f2a100d0e2b0f2a102a0e2b0e0e0f0e0e2b0f0e0e2b0e2b0f2a0f2a100d0f2a1000099572390f0e0e2b0f0d0f0e0f0e0e0e0f0e0e0e0f0e0f0e0e0e0f0e0e0e0f2b0f0d0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f0e0e2b0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f0e0e2b0f0e0e2b0f2a0f2a102a0f0d0f0e0e2b0f0d0f2b0f2a0f2a0f2a100d0e2b0f000d05000000000000';
$results = broadlink::sendCommands('192.168.10.134','3a:6d:00:77:0f:78',10039,$data);

print_r($results);