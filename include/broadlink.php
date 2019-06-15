<?php

class broadlink
{
    protected $name;
    protected $host;
    protected $mac_address;
    protected $port;
    protected $timeout;
    protected $count;
    protected $key;
    protected $iv;
    protected $id;
    protected $device_type;
    protected $model;

    public function __construct(string $host, string $mac_address, string $device_type, int $port = 80)
    {

        // Set Global Vars
        $this->timeout = 10;
        $this->key = [0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02];
        $this->iv = [0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58];
        $this->id = [0, 0, 0, 0];

        $this->host = $host;
        $this->port = $port;
        $this->device_type = $device_type;

        $this->mac_address = [];
        $mac_str_array = explode(':', $mac_address);
        foreach (array_reverse($mac_str_array) as $value) {
            array_push($this->mac_address, hexdec($value));
        }

        $this->count = rand(0, 0xffff);
    }

    public function padZero(string $data): string
    {
        $len = 16;
        if (strlen($data) % $len) {
            $padLength = $len - strlen($data) % $len;
            $data .= str_repeat("\0", $padLength);
        }
        return $data;
    }

    public function decrypt(string $key, string $data, string $iv): string
    {
        return openssl_decrypt($data, 'AES-128-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
    }

    public function encrypt(string $key, string $data, string $iv): string
    {
        return openssl_encrypt(self::padZero($data), 'AES-128-CBC', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
    }

    public static function discover(): array
    {

        $devices = [];
        try {
            $s = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
            socket_connect($s, '8.8.8.8', 53);  // connecting to a UDP address doesn't send packets
            socket_getsockname($s, $local_ip_address, $port);
            socket_close($s);

            $cs = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

            if ($cs) {
                socket_set_option($cs, SOL_SOCKET, SO_REUSEADDR, 1);
                socket_set_option($cs, SOL_SOCKET, SO_BROADCAST, 1);
                socket_set_option($cs, SOL_SOCKET, SO_RCVTIMEO, array('sec' => 1, 'usec' => 0));
                socket_bind($cs, 0, 0);
            }

            $address = explode('.', $local_ip_address);
            $packet = self::byteArray(0x30);

            $timezone = (int)intval(date("Z")) / -3600;
            $year = date("Y");

            if ($timezone < 0) {
                $packet[0x08] = 0xff + $timezone - 1;
                $packet[0x09] = 0xff;
                $packet[0x0a] = 0xff;
                $packet[0x0b] = 0xff;
            } else {

                $packet[0x08] = $timezone;
                $packet[0x09] = 0;
                $packet[0x0a] = 0;
                $packet[0x0b] = 0;
            }

            $packet[0x0c] = $year & 0xff;
            $packet[0x0d] = $year >> 8;
            $packet[0x0e] = intval(date("i"));
            $packet[0x0f] = intval(date("H"));
            $sub_year = substr($year, 2);
            $packet[0x10] = intval($sub_year);
            $packet[0x11] = intval(date('N'));
            $packet[0x12] = intval(date("d"));
            $packet[0x13] = intval(date("m"));
            $packet[0x18] = intval($address[0]);
            $packet[0x19] = intval($address[1]);
            $packet[0x1a] = intval($address[2]);
            $packet[0x1b] = intval($address[3]);
            $packet[0x1c] = $port & 0xff;
            $packet[0x1d] = $port >> 8;
            $packet[0x26] = 6;

            $checksum = 0xbeaf;

            for ($i = 0; $i < sizeof($packet); $i++) {
                $checksum += $packet[$i];
            }

            $checksum = $checksum & 0xffff;

            $packet[0x20] = $checksum & 0xff;
            $packet[0x21] = $checksum >> 8;

            socket_sendto($cs, self::byte($packet), sizeof($packet), 0, "255.255.255.255", 80);
            while (socket_recvfrom($cs, $response, 1024, 0, $from, $port)) {

                $host = '';
                $response_packet = self::byteToArray($response);

                $device_type = hexdec(sprintf("%x%x", $response_packet[0x35], $response_packet[0x34]));
                $host_array = array_slice($response_packet, 0x36, 4);
                $mac_address = array_slice($response_packet, 0x3a, 6);
                $mac_address_str = implode(":", array_map("dechex", $mac_address));

                foreach (array_reverse($host_array) as $ip) {
                    $host .= $ip . ".";
                }

                $host = substr($host, 0, strlen($host) - 1);
                $device = self::createDevice($host, $mac_address_str, $device_type);

                if ($device != NULL) {
                    $device->model = self::getDeviceType($device_type)[1];
                    $device->device_type =  $device_type;
                    $device->name = str_replace("\0", '', self::byte(array_slice($response_packet, 0x40)));
                    array_push($devices, $device);
                }
            }

            if ($cs) {
                socket_close($cs);
            }
        } catch (Exception $e) {

        }

        return $devices;
    }

    public static function createDevice(string $host, string $mac_address, string $device_type, int $port = 80)
    {

        $device_type_info = self::getDeviceType($device_type);
        $device_type_id = $device_type_info[0];

        switch ($device_type_id) {
            case 0:
                return new SP1($host, $mac_address, $device_type, $port);
                break;
            case 1:
                return new SP2($host, $mac_address, $device_type, $port);
                break;
            case 2:
                return new RM($host, $mac_address, $device_type, $port);
                break;
            case 3:
                return new A1($host, $mac_address, $device_type, $port);
                break;
            case 4:
                return new MP1($host, $mac_address, $device_type, $port);
                break;
            default:
                break;
        }

        return NULL;
    }

    public static function getDeviceType(string $device_type): array
    {
        $type = -1;
        $label = "Unknown";

        switch ($device_type) {
            case 0:
                $type = 0;
                $label = "SP1";
                break;
            case 0x2711:
                $type = 1;
                $label = "SP2";
                break;
            case 0x2719:
            case 0x7919:
            case 0x271a:
            case 0x791a:
                $type = 1;
                $label = "Honeywell SP2";
                break;
            case 0x2720:
                $type = 1;
                $label = "SPMini";
                break;
            case 0x753e:
                $type = 1;
                $label = "SP3";
                break;
            case 0x7D00:
                $type = 1;
                $label = "OEM branded SP3";
                break;
            case 0x947a:
            case 0x9479:
                $type = 1;
                $label = "SP3S";
                break;
            case 0x2728:
                $type = 1;
                $label = "SPMini2";
                break;
            case 0x2733:
            case 0x273e:
                $type = 1;
                $label = "OEM branded SPMini";
                break;
            case 0x7530:
            case 0x7918:
                $type = 1;
                $label = "OEM branded SPMini2";
                break;
            case 0x2736:
                $type = 1;
                $label = "SPMiniPlus";
                break;
            case 0x2712:
                $type = 2;
                $label = "RM2";
                break;
            case 0x2737:
                $type = 2;
                $label = "RM Mini";
                break;
            case 0x273d:
                $type = 2;
                $label = "RM Pro Phicomm";
                break;
            case 0x2783:
                $type = 2;
                $label = "RM2 Home Plus";
                break;
            case 0x277c:
                $type = 2;
                $label = "RM2 Home Plus GDT";
                break;
            case 0x272a:
                $type = 2;
                $label = "RM2 Pro Plus";
                break;
            case 0x2787:
                $type = 2;
                $label = "RM2 Pro Plus2";
                break;
            case 0x279d:
                $type = 2;
                $label = "RM2 Pro Plus3";
                break;
            case 0x27a9:
                $type = 2;
                $label = "RM2 Pro Plus_300";
                break;
            case 0x278b:
                $type = 2;
                $label = "RM2 Pro Plus BL";
                break;
            case 0x2797:
                $type = 2;
                $label = "RM2 Pro Plus HYC";
                break;
            case 0x27a1:
                $type = 2;
                $label = "RM2 Pro Plus R1";
                break;
            case 0x27a6:
                $type = 2;
                $label = "RM2 Pro PP";
                break;
            case 0x278f:
                $type = 2;
                $label = "RM Mini Shate";
                break;
            case 0x27c2:
                $type = 2;
                $label = "RM Mini 3";
                break;
            case 0x2714:
                $type = 3;
                $label = "A1";
                break;
            case 0x4EB5:
                $type = 4;
                $label = "MP1";
                break;
            case 0x4EF7:
                $type = 4;
                $label = "Honyar oem mp1";
                break;
            case 0x4EAD:
                $type = -1;
                $label = "Hysen controller";
                break;
            case 0x2722:
                $type = -1;
                $label = "S1 (SmartOne Alarm Kit)";
                break;
            case 0x4E4D:
                $type = -1;
                $label = "Dooya DT360E (DOOYA_CURTAIN_V2)";
                break;
            default:
                break;
        }

        return [$type, $label];
    }

    public function deviceInfo(): array
    {

        $mac_address = "";
        foreach ($this->mac_address as $value) {
            $mac_address = sprintf("%02x", $value) . ':' . $mac_address;
        }

        $mac_address = substr($mac_address, 0, strlen($mac_address) - 1);
        $host = $this->host;
        $name = $this->name;
        $device_type = sprintf("0x%x", $this->device_type);
        $device_type = is_string($device_type) ? hexdec($device_type) : $device_type;
        $model = self::getDeviceType($device_type)[1];

        return ['name' => $name, 'device_type' => $device_type, 'model' => $model, 'host' => $host, 'mac_address' => $mac_address];
    }

    public function authenticate(): bool
    {

        $start_time = time();
        $authenticated = false;
        while (true) {
            $auth = self::authenticateProcess();
            if ($auth) {
                $authenticated = true;
                break;
            }
            if ((time() - $start_time) > 5) {
                break;
            }
        }

        return $authenticated;
    }

    public function authenticateProcess(): bool
    {

        $payload = $this->byteArray(0x50);

        $payload[0x04] = 0x31;
        $payload[0x05] = 0x31;
        $payload[0x06] = 0x31;
        $payload[0x07] = 0x31;
        $payload[0x08] = 0x31;
        $payload[0x09] = 0x31;
        $payload[0x0a] = 0x31;
        $payload[0x0b] = 0x31;
        $payload[0x0c] = 0x31;
        $payload[0x0d] = 0x31;
        $payload[0x0e] = 0x31;
        $payload[0x0f] = 0x31;
        $payload[0x10] = 0x31;
        $payload[0x11] = 0x31;
        $payload[0x12] = 0x31;
        $payload[0x1e] = 0x01;
        $payload[0x2d] = 0x01;
        $payload[0x30] = ord('T');
        $payload[0x31] = ord('e');
        $payload[0x32] = ord('s');
        $payload[0x33] = ord('t');
        $payload[0x34] = ord(' ');
        $payload[0x35] = ord(' ');
        $payload[0x36] = ord('1');

        $response = $this->sendPacket(0x65, $payload);
        $enc_payload = array_slice($response, 0x38);
        $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));

        if (count(array_slice($payload, 0x04, 16)) % 16 != 0) {
            return false;
        }

        $this->id = array_slice($payload, 0x00, 4);
        $this->key = array_slice($payload, 0x04, 16);

        return true;
    }

    public function sendPacket(string $command, array $payload): array
    {

        $myResponse = [];
        try {
            $cs = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);

            if ($cs) {
                socket_set_option($cs, SOL_SOCKET, SO_REUSEADDR, 1);
                socket_set_option($cs, SOL_SOCKET, SO_BROADCAST, 1);
                socket_bind($cs, 0, 0);
            }

            $this->count = ($this->count + 1) & 0xffff;

            $packet = $this->byteArray(0x38);

            $packet[0x00] = 0x5a;
            $packet[0x01] = 0xa5;
            $packet[0x02] = 0xaa;
            $packet[0x03] = 0x55;
            $packet[0x04] = 0x5a;
            $packet[0x05] = 0xa5;
            $packet[0x06] = 0xaa;
            $packet[0x07] = 0x55;
            $packet[0x24] = 0x2a;
            $packet[0x25] = 0x27;
            $packet[0x26] = $command;
            $packet[0x28] = $this->count & 0xff;
            $packet[0x29] = $this->count >> 8;
            $packet[0x2a] = $this->mac_address[0];
            $packet[0x2b] = $this->mac_address[1];
            $packet[0x2c] = $this->mac_address[2];
            $packet[0x2d] = $this->mac_address[3];
            $packet[0x2e] = $this->mac_address[4];
            $packet[0x2f] = $this->mac_address[5];
            $packet[0x30] = $this->id[0];
            $packet[0x31] = $this->id[1];
            $packet[0x32] = $this->id[2];
            $packet[0x33] = $this->id[3];

            $checksum = 0xbeaf;
            for ($i = 0; $i < sizeof($payload); $i++) {
                $checksum += $payload[$i];
                $checksum = $checksum & 0xffff;
            }

            $aes = $this->byteToArray(self::encrypt($this->key(), $this->byte($payload), $this->iv()));

            $packet[0x34] = $checksum & 0xff;
            $packet[0x35] = $checksum >> 8;

            for ($i = 0; $i < sizeof($aes); $i++) {
                array_push($packet, $aes[$i]);
            }

            $checksum = 0xbeaf;
            for ($i = 0; $i < sizeof($packet); $i++) {
                $checksum += $packet[$i];
                $checksum = $checksum & 0xffff;
            }

            $packet[0x20] = $checksum & 0xff;
            $packet[0x21] = $checksum >> 8;

            $from = '';
            socket_sendto($cs, $this->byte($packet), sizeof($packet), 0, $this->host, $this->port);
            socket_set_option($cs, SOL_SOCKET, SO_RCVTIMEO, ['sec' => $this->timeout, 'usec' => 0]);
            socket_recvfrom($cs, $response, 1024, 0, $from, $port);

            if ($cs) {
                socket_close($cs);
            }

            $myResponse = $this->byteToArray($response);
        } catch (Exception $e) {
        }

        return $myResponse;

    }

    public static function sendCommands( string $host, string $mac_address, string $device_type, string $command, int $repeat = 1): array
    {
        $total_start_time = time();
        $success = 0;
        $error = 0;
        $error_msg = "";
        $results = [];
        $response = "";
        $rm = self::createDevice($host, $mac_address,$device_type);

        // Repeat
        for ($i = 0; $i < $repeat; $i++) {

            $auth = $rm->authenticate();
            if($auth) {
                $response = 200;
                if(method_exists($rm,'sendData')) {
                    $rm->sendData($command);
                    $success++;
                }
            }else{
                $error++;
                $error_msg = 'Could not Authenticate';
            }

            // Response
            array_push($results, [$response, '', $error_msg]);
        }

        // Total Time
        $total_start_time = (time() - $total_start_time);
        return ['error' => $error, 'success' => $success, 'results' => $results, 'total_time' => $total_start_time];
    }

    public static function convertPronto2Broadlink($code){
        $pulses = self::pronto2lirc($code);
        $packets = self::lirc2broadlink($pulses);
        return implode(array_map('bin2hex',$packets));
    }

    protected static function byteArray(int $size): array
    {
        $packet = [];
        for ($i = 0; $i < $size; $i++) {
            $packet[$i] = 0;
        }
        return $packet;
    }

    protected static function byte(array $array): string
    {
        return implode(array_map("chr", $array));
    }

    protected static function byteToArray(string $data): array
    {
        return array_merge(unpack('C*', $data));
    }

    protected function key(): string
    {
        return implode(array_map("chr", $this->key));
    }

    protected function iv(): string
    {
        return implode(array_map("chr", $this->iv));
    }

    private static function pronto2lirc($protoHex){
        $codes = [];
        $proto_hexes = explode(" ", $protoHex);
        foreach($proto_hexes as $hex_pair){
            $first_hex = hexdec ($hex_pair);
            $codes[] = $first_hex;
        }

        if ($codes[0]){
            echo "Pronto code should start with 0000";
            return false;
        }else if (count($codes) != (4 + 2 * ($codes[2] + $codes[3]))){
            echo "Number of pulse widths does not match the preamble";
            return false;
        }

        $frequency = 1 / ($codes[1] * 0.241246);
        $lirc = [];
        foreach(array_slice($codes,4) as $code){
            $lirc[] = (int) round ($code/$frequency);
        }

        return $lirc;
    }

    private static function lirc2broadlink($pulses){
        $array = [];
        foreach($pulses as $pulse){
            $current_pulse = $pulse * 269 / 8192;  # 32.84ms units

            if ($current_pulse < 256) {
                $array[]= pack('C', $current_pulse);  # big endian (1-byte)
            }else{
                $array[]= pack('c*', 0x00);
                $array[]= pack('n', $current_pulse);  # big endian (2-bytes)
            }

        }

        $packet[] = pack('c*', 0x26, 0x00);
        $packet[] = pack('v', count($array)+1);  # little endian byte count /unsigned short (always 16 bit, little endian byte order)
        $packet = array_merge($packet, $array);
        $packet[] = pack('c*', 0x0d, 0x05);


        # Add 0s to make ultimate packet size a multiple of 16 for 128-bit AES encryption.
        $remainder = (int) (count($packet) + 4 + 4) % 16;  # rm.send_data() adds 4-byte header (02 00 00 00)
        if($remainder >0 ) {
            $packet[] = (16 - $remainder);
        }

        return $packet;
    }
}

class SP1 extends broadlink
{

    function __construct(string $host, string $mac_address, string $device_type, int $port)
    {
        parent::__construct($host, $mac_address, $device_type, $port);
    }

    public function setPower(string $state)
    {
        $packet = self::byteArray(4);
        $packet[0] = $state;
        $this->sendPacket(0x66, $packet);
    }

}

class SP2 extends broadlink
{

    function __construct(string $host, string $mac_address, string $device_type, int $port)
    {
        parent::__construct($host, $mac_address, $device_type, $port);
    }

    public function setPower(string $state)
    {
        $packet = self::byteArray(16);
        $packet[0] = 0x02;

        if (self::checkNightLight()) {
            $packet[4] = $state ? 3 : 2;
        } else {
            $packet[4] = $state ? 1 : 0;
        }

        $this->sendPacket(0x6a, $packet);
    }

    public function checkNightLight():bool
    {
        // Returns the power state of the smart plug.
        $packet = self::byteArray(16);
        $packet[0] = 0x01;
        $response = $this->sendPacket(0x6a, $packet);
        $err = hexdec(sprintf("%x%x", $response[0x23], $response[0x22]));

        if ($err == 0) {
            $enc_payload = array_slice($response, 0x38);
            if (count($enc_payload) > 0) {
                $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));
                return ($payload[0x4] == 2 || $payload[0x4] == 3 || $payload[0x4] == 0xFF) ? true : false;
            }
        }

        return false;
    }

    public function setNightLight(bool $state)
    {
        $packet = self::byteArray(16);
        $packet[0] = 0x02;
        $packet[4] = $state ? 1 : 0;

        if (self::checkPower()) {
            $packet[4] = $state ? 3 : 1;
        } else {
            $packet[4] = $state ? 2 : 0;
        }

        $this->sendPacket(0x6a, $packet);
    }

    public function checkPower() : bool
    {
        // Returns the power state of the smart plug.
        $packet = self::byteArray(16);
        $packet[0] = 0x01;
        $response = $this->sendPacket(0x6a, $packet);
        $err = hexdec(sprintf("%x%x", $response[0x23], $response[0x22]));

        if ($err == 0) {
            $enc_payload = array_slice($response, 0x38);
            if (count($enc_payload) > 0) {
                $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));
                return ($payload[0x4] == 1 || $payload[0x4] == 3 || $payload[0x4] == 0xFD) ? true : false;
            }
        }

        return false;
    }

    public function getEnergy(): float
    {
        $packet = self::byteArray(10);
        $packet[0] = 0x08;
        $packet[1] = 0x00;
        $packet[2] = 0x254;
        $packet[3] = 0x01;
        $packet[4] = 0x05;
        $packet[5] = 0x01;
        $packet[6] = 0x00;
        $packet[7] = 0x00;
        $packet[8] = 0x00;
        $packet[9] = 0x45;

        $response = $this->sendPacket(0x6a, $packet);
        $err = hexdec(sprintf("%x%x", $response[0x23], $response[0x22]));

        if ($err == 0) {
            $enc_payload = array_slice($response, 0x38);
            if (count($enc_payload) > 0) {
                $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));
                $energy = ($payload[0x07] * 256 + substr($payload[0x06], 2)) + substr($payload[0x05], 2) / 100;
                return $energy;
            }
        }

        return 0;
    }

}

class A1 extends broadlink
{

    function __construct(string $host, string $mac_address, string $device_type, int $port)
    {
        parent::__construct($host, $mac_address, $device_type, $port);
    }

    public function checkSensors():array
    {

        $data = [];
        $packet = self::byteArray(16);
        $packet[0] = 0x01;
        $response = $this->sendPacket(0x6a, $packet);
        $err = hexdec(sprintf("%x%x", $response[0x23], $response[0x22]));

        if ($err == 0) {
            $enc_payload = array_slice($response, 0x38);
            if (count($enc_payload) > 0) {
                $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));
                $data['temperature'] = ($payload[0x4] * 10 + $payload[0x5]) / 10.0;
                $data['humidity'] = ($payload[0x6] * 10 + $payload[0x7]) / 10.0;
                $data['light'] = $payload[0x8];
                $data['air_quality'] = $payload[0x0a];
                $data['noise'] = $payload[0x0c];

                switch ($data['light']) {
                    case 0:
                        $data['light_word'] = 'dark';
                        break;
                    case 1:
                        $data['light_word'] = 'dim';
                        break;
                    case 2:
                        $data['light_word'] = 'normal';
                        break;
                    case 3:
                        $data['light_word'] = 'bright';
                        break;
                    default:
                        $data['light_word'] = 'unknown';
                        break;
                }

                switch ($data['air_quality']) {
                    case 0:
                        $data['air_quality_word'] = 'excellent';
                        break;
                    case 1:
                        $data['air_quality_word'] = 'good';
                        break;
                    case 2:
                        $data['air_quality_word'] = 'normal';
                        break;
                    case 3:
                        $data['air_quality_word'] = 'bad';
                        break;
                    default:
                        $data['air_quality_word'] = 'unknown';
                        break;
                }

                switch ($data['noise']) {
                    case 0:
                        $data['noise_word'] = 'quiet';
                        break;
                    case 1:
                        $data['noise_word'] = 'normal';
                        break;
                    case 2:
                        $data['noise_word'] = 'noisy';
                        break;
                    default:
                        $data['noise_word'] = 'unknown';
                        break;
                }
            }
        }

        return $data;
    }

    public function checkSensorsRaw():array
    {

        $data = [];
        $packet = self::byteArray(16);
        $packet[0] = 0x01;
        $response = $this->sendPacket(0x6a, $packet);
        $err = hexdec(sprintf("%x%x", $response[0x23], $response[0x22]));

        if ($err == 0) {
            $enc_payload = array_slice($response, 0x38);
            if (count($enc_payload) > 0) {
                $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));
                $data['temperature'] = ($payload[0x4] * 10 + $payload[0x5]) / 10.0;
                $data['humidity'] = ($payload[0x6] * 10 + $payload[0x7]) / 10.0;
                $data['light'] = $payload[0x8];
                $data['air_quality'] = $payload[0x0a];
                $data['noise'] = $payload[0x0c];
            }
        }

        return $data;
    }

}

class RM extends broadlink
{

    function __construct(string $host, string $mac_address, string $device_type, int $port)
    {
        parent::__construct($host, $mac_address, $device_type, $port);
    }

    public function learningMode()
    {
        $packet = self::byteArray(16);
        $packet[0] = 0x03;
        $this->sendPacket(0x6a, $packet);
    }

    public function sendData($data)
    {
        $packet = self::byteArray(4);
        $packet[0] = 0x02;
        if (is_array($data)) {
            $packet = array_merge($packet, $data);
        } else {
            for ($i = 0; $i < strlen($data); $i += 2) {
                array_push($packet, hexdec(substr($data, $i, 2)));
            }
        }

        return $this->sendPacket(0x6a, $packet);
    }

    public function checkData():array
    {

        $code = [];
        $packet = self::byteArray(16);
        $packet[0] = 0x04;
        $response = $this->sendPacket(0x6a, $packet);
        $err = hexdec(sprintf("%x%x", $response[0x23], $response[0x22]));

        if ($err == 0) {
            $enc_payload = array_slice($response, 0x38);
            if (count($enc_payload) > 0) {
                $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));
                $code = array_slice($payload, 0x04);
            }
        }

        return $code;
    }

    public function checkTemperature():float
    {
        $temp = 0;
        $packet = $this->byteArray(16);
        $packet[0] = 0x01;
        $response = $this->sendPacket(0x6a, $packet);
        $err = hexdec(sprintf("%x%x", $response[0x23], $response[0x22]));

        if ($err == 0) {
            $enc_payload = array_slice($response, 0x38);
            if (count($enc_payload) > 0) {
                $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));
                $temp = ($payload[0x4] * 10 + $payload[0x5]) / 10.0;
            }
        }

        return $temp;
    }
}

class MP1 extends broadlink
{

    function __construct(string $host, string $mac_address, string $device_type, int $port)
    {
        parent::__construct($host, $mac_address, $device_type, $port);
    }

    public function setPower($sid, $state)
    {

        $sid_mask = 0x01 << ($sid - 1);
        self::setPowerMask($sid_mask, $state);
    }

    public function setPowerMask(int $sid_mask,bool $state)
    {
        $packet = self::byteArray(16);
        $packet[0x00] = 0x0d;
        $packet[0x02] = 0xa5;
        $packet[0x03] = 0xa5;
        $packet[0x04] = 0x5a;
        $packet[0x05] = 0x5a;
        $packet[0x06] = 0xb2 + ($state ? ($sid_mask << 1) : $sid_mask);
        $packet[0x07] = 0xc0;
        $packet[0x08] = 0x02;
        $packet[0x0a] = 0x03;
        $packet[0x0d] = $sid_mask;
        $packet[0x0e] = $state ? $sid_mask : 0;

        $this->sendPacket(0x6a, $packet);
    }

    public function checkPower():array
    {
        $data = [];
        if ($state = $this->checkPowerRaw()) {
            $data[0] = (bool)($state & 0x01);
            $data[1] = (bool)($state & 0x02);
            $data[2] = (bool)($state & 0x04);
            $data[3] = (bool)($state & 0x08);
        }

        return $data;
    }

    public function checkPowerRaw():bool
    {

        $packet = self::byteArray(16);
        $packet[0x00] = 0x0a;
        $packet[0x02] = 0xa5;
        $packet[0x03] = 0xa5;
        $packet[0x04] = 0x5a;
        $packet[0x05] = 0x5a;
        $packet[0x06] = 0xae;
        $packet[0x07] = 0xc0;
        $packet[0x08] = 0x01;

        $response = $this->sendPacket(0x6a, $packet);
        $err = hexdec(sprintf("%x%x", $response[0x23], $response[0x22]));

        if ($err == 0) {
            $enc_payload = array_slice($response, 0x38);
            if (count($enc_payload) > 0) {
                $payload = $this->byteToArray(self::decrypt($this->key(), $this->byte($enc_payload), $this->iv()));
                return $payload[0x0e];
            }
        }

        return false;
    }

}
