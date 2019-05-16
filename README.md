# PHP control for Broadlink RM2 IR controllers

A simple PHP Class for controlling IR controllers from Broadlink. At present, the following devices are currently supported:

* RM Pro (referred to as RM2 in the codebase)
* A1 sensor platform devices are supported
* RM3 mini IR blaster

There is currently no support for the cloud API.

This is a fork of [tasict/broadlink-device-php](https://github.com/tasict/broadlink-device-php)
which used the Python Broadlink repo [mjg59/python-broadlink](https://github.com/mjg59/python-broadlink/blob/master/README.md)

I updated the PHP class to include:
 * Support more Broadlink devices
 * Use OpenSSL instead of the depreciated mcrypt for encryption
 * Minor refactored of code
 * Added a loop to try to authenticate a couple of times before failing 
 * Updated examples to be CLI and allow for quick exit when learning buttons
 
 
## Example Use
You need to setup your Broadlink RM Device to your Wifi Network using the normal setup method provided by Broadlink.
 
You need to obtain the authentication key required for communicating with your device.
 
### Sending a Command after authenticating 
```
include("include/broadlink.php");

$rm = broadlink::createDevice('192.168.10.134','87:f0:77:00:3d:3a', 80, 0x2737);
$auth = $rm->authenticate();

if($auth) {
    $data = '260032017139100d0f2a0f0e0f0d0f0e0f0e0e0e0f0e0e0e0f0e0f0e0e0e0f0e0e2b0f0e0e0e0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f2b0f0d0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f2b0f0d0f2a102a0f2a0f2a0f0e0e0e0f2a100d0e2b0f2a1029102a0f0d0f2a1000099572390f0e0e2b0f0e0f0d0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f0e0e0f0f2a0e0e0f0e0f0e0e0e0f0e0f0d0f0e0e0f0e0e0f2a100d0e0f0e0e0f0e0e0e100d0e0f0e0e0f2a100d0e2b0f2a102a0e2b0e0e0f0e0e2b0f0e0e2b0e2b0f2a0f2a100d0f2a1000099572390f0e0e2b0f0d0f0e0f0e0e0e0f0e0e0e0f0e0f0e0e0e0f0e0e0e0f2b0f0d0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f0e0e2b0f0e0e0e0f0e0e0f0e0e0f0e0e0e0f0e0e2b0f0e0e2b0f2a0f2a102a0f0d0f0e0e2b0f0d0f2b0f2a0f2a0f2a100d0e2b0f000d05000000000000';
    $rm->sendData($data);
}
```
 
See the examples of how to run discover to find devices and learn new codes.

