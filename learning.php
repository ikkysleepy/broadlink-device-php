<?php
include("include/broadlink.php");

$rm = broadlink::createDevice('192.168.10.134','87:f0:77:00:3d:3a', 80, 0x2737);
$auth = $rm->authenticate();

if ($auth) {
    $rm->learningMode();
    echo "Press Button...\n\n";

    $start_time = time();
    $authenticated = false;
    $hex_number = '';
    while (true) {
        $command = $rm->checkData();
        if (!empty($command)) {
            foreach ($command as $value) {
                $hex_number .= sprintf("%02x", $value);
            }

            break;
        }

        if ((time() - $start_time) > 7) {
            break;
        }

    }
    print_r($hex_number);
} else {
    echo "Could not authenticate\n";
}