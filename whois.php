<?php

function getWhoisServer($server, $port, $domainName)
{
    // Open a Socket connection to our WHOIS server
    $fp = fsockopen($server, $port);
    
    $headerOut = "$domainName\r\n";
    
    // Send the data
    fwrite($fp, $headerOut);

    while (!feof($fp)) {
        $whois = fgets($fp, 128);
        if(stripos($whois, "whois:") > -1) {
            fclose($fp);
            $whoisServer = explode(":", $whois);
            $whoisServer = trim($whoisServer[1]);
            return getWhoisServer($whoisServer, $port, $domainName);
            break;
        } else {
            if(stripos($whois, "expir") > -1) {
                $output = $whois;
                break;
            }
        }
    }
    return $output;
    fclose($fp);

}

function esip($ip_addr)
{
    //first of all the format of the ip address is matched 
    if (preg_match("/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/", $ip_addr)) {
        //now all the intger values are separated 
        $parts = explode(".", $ip_addr);
        //now we need to check each part can range from 0-255 
        foreach ($parts as $ip_parts) {
            if (intval($ip_parts) > 255 || intval($ip_parts) < 0)
                return FALSE; //if number is not within range of 0-255 
        }
        return TRUE;
    } else
        return FALSE; //if format of ip address doesn't matches 
}


function domain($domainb)
{
    $bits = explode('/', $domainb);
    if ($bits[0] == 'http:' || $bits[0] == 'https:') {
        $domainb = $bits[2];
    } else {
        $domainb = $bits[0];
    }
    unset($bits);
    $bits = explode('.', $domainb);
    $idz = count($bits);
    $idz -= 3;
    if (strlen($bits[($idz + 2)]) == 2) {
        $url = $bits[$idz] . '.' . $bits[($idz + 1)] . '.' . $bits[($idz + 2)];
    } else if (strlen($bits[($idz + 2)]) == 0) {
        $url = $bits[($idz)] . '.' . $bits[($idz + 1)];
    } else {
        $url = $bits[($idz + 1)] . '.' . $bits[($idz + 2)];
    }
    return $url;
}

function doMain($address) {
    $parsed_url = parse_url($address);
    $check = esip($parsed_url['host']);
    $host = $parsed_url['host'];
    if ($check == FALSE) {
        if ($host != "") {
            $host = domain($host);
        } else {
            $host = domain($address);
        }
    }
}
echo getWhoisServer("whois.iana.org", 43, $host);