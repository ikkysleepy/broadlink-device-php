<?
include("include/broadlink.php");

$result = array();
$devices = broadlink::discover();
foreach ($devices as $device) {
	$obj = $device->deviceInfo();

	if($obj['model'] == "RM2"){
		$auth = $device->authenticate();
		if($auth) {
            $temperature = $device->checkTemperature();
            $obj['temperature'] = $temperature;
        }
	}
	else if($obj['model'] == "A1"){
		$auth = $device->authenticate();
		if($auth) {
            $data = $device->checkSensors();
            $obj = array_merge($obj, $data);
        }
	}

	array_push($result, $obj);
}

print_r($result);
