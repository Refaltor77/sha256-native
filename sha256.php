<?php

# values get in source code php of the function 'hash'
$k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

$h = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

function rotr($x, $n) {
    return ($x >> $n) | ($x << (32 - $n));
}

function ch($x, $y, $z) {
    return ($x & $y) ^ (~$x & $z);
}

function maj($x, $y, $z) {
    return ($x & $y) ^ ($x & $z) ^ ($y & $z);
}

function sigma0($x) {
    return rotr($x, 2) ^ rotr($x, 13) ^ rotr($x, 22);
}

function sigma1($x) {
    return rotr($x, 6) ^ rotr($x, 11) ^ rotr($x, 25);
}

function delta0($x) {
    return rotr($x, 7) ^ rotr($x, 18) ^ ($x >> 3);
}

function delta1($x) {
    return rotr($x, 17) ^ rotr($x, 19) ^ ($x >> 10);
}

function sha256($data) {
    global $k, $h;
    
    $originalBitLength = strlen($data) * 8;
    $data .= chr(0x80);
    while ((strlen($data) * 8) % 512 !== 448) {
        $data .= chr(0x00);
    }
    
    $data .= pack('N2', 0, $originalBitLength);
    
    $blocks = str_split($data, 64);

    foreach ($blocks as $block) {
        $w = [];
        foreach (str_split($block, 4) as $chunk) {
            $w[] = unpack('N', $chunk)[1];
        }
        
        for ($i = 16; $i < 64; $i++) {
            $w[$i] = delta1($w[$i - 2]) + $w[$i - 7] + delta0($w[$i - 15]) + $w[$i - 16];
            $w[$i] &= 0xFFFFFFFF;
        }
        
        list($a, $b, $c, $d, $e, $f, $g, $h0) = $h;
        
        for ($i = 0; $i < 64; $i++) {
            $t1 = $h0 + sigma1($e) + ch($e, $f, $g) + $k[$i] + $w[$i];
            $t2 = sigma0($a) + maj($a, $b, $c);

            $h0 = $g;
            $g = $f;
            $f = $e;
            $e = ($d + $t1) & 0xFFFFFFFF;
            $d = $c;
            $c = $b;
            $b = $a;
            $a = ($t1 + $t2) & 0xFFFFFFFF;
        }
        
        $h = [
            ($h[0] + $a) & 0xFFFFFFFF,
            ($h[1] + $b) & 0xFFFFFFFF,
            ($h[2] + $c) & 0xFFFFFFFF,
            ($h[3] + $d) & 0xFFFFFFFF,
            ($h[4] + $e) & 0xFFFFFFFF,
            ($h[5] + $f) & 0xFFFFFFFF,
            ($h[6] + $g) & 0xFFFFFFFF,
            ($h[7] + $h0) & 0xFFFFFFFF
        ];
    }
    
    $hash = '';
    foreach ($h as $value) {
        $hash .= sprintf('%08x', $value);
    }

    return $hash;
}


$data = "mon_mot_de_passe";
$hash = sha256($data);
$hash2 = hash('sha256', $data);

echo "Correct : " . ($hash === $hash2 ? "oui" : "non");
