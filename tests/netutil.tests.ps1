# netutil.tests.ps1 - shared IP/CIDR math.
. "$PSScriptRoot\_assert.ps1"
Import-Module "$PSScriptRoot\..\src\tier1\modules\netutil.psm1" -Force

# --- Test-IpInCidr (v4) ---
Assert-True  (Test-IpInCidr -Ip '10.1.2.3' -Cidr '10.0.0.0/8')        '10.1.2.3 in 10/8'
Assert-False (Test-IpInCidr -Ip '11.0.0.1' -Cidr '10.0.0.0/8')        '11.0.0.1 not in 10/8'
Assert-True  (Test-IpInCidr -Ip '149.154.161.5' -Cidr '149.154.160.0/20') 'telegram range'
Assert-False (Test-IpInCidr -Ip '149.154.176.1' -Cidr '149.154.160.0/20') 'just past /20'
Assert-True  (Test-IpInCidr -Ip '198.51.100.13' -Cidr '198.51.100.13/32') 'exact /32'
Assert-False (Test-IpInCidr -Ip '198.51.100.14' -Cidr '198.51.100.13/32') 'neighbor /32'
# non-aligned base address: /20 must mask the base too
Assert-True  (Test-IpInCidr -Ip '149.154.160.1' -Cidr '149.154.165.0/20') 'unaligned cidr base masked'
# v6
Assert-True  (Test-IpInCidr -Ip 'fe80::1' -Cidr 'fe80::/10')          'v6 link-local block'
Assert-False (Test-IpInCidr -Ip '2001:db8::1' -Cidr 'fe80::/10')      'v6 outside block'
# family mismatch is false, not an error
Assert-False (Test-IpInCidr -Ip '10.0.0.1' -Cidr 'fe80::/10')         'family mismatch false'
# garbage input is false, not an error
Assert-False (Test-IpInCidr -Ip 'not-an-ip' -Cidr '10.0.0.0/8')       'garbage ip false'
Assert-False (Test-IpInCidr -Ip '10.0.0.1' -Cidr 'garbage')           'garbage cidr false'

# --- Test-NonRoutableIp ---
Assert-Equal 'loopback'   (Test-NonRoutableIp -Ip '127.0.0.1')   'v4 loopback'
Assert-Equal 'loopback'   (Test-NonRoutableIp -Ip '::1')         'v6 loopback'
Assert-Equal 'link-local' (Test-NonRoutableIp -Ip '169.254.10.1') 'v4 link-local'
Assert-Equal 'link-local' (Test-NonRoutableIp -Ip 'fe80::abcd')  'v6 link-local'
Assert-Equal 'rfc1918'    (Test-NonRoutableIp -Ip '10.0.0.1')    '10/8'
Assert-Equal 'rfc1918'    (Test-NonRoutableIp -Ip '172.16.0.1')  '172.16/12'
Assert-Null  (Test-NonRoutableIp -Ip '172.15.0.1')               '172.15 is public'
Assert-Null  (Test-NonRoutableIp -Ip '172.32.0.1')               '172.32 is public'
Assert-Equal 'rfc1918'    (Test-NonRoutableIp -Ip '192.168.1.1') '192.168/16'
Assert-Equal 'cgnat'      (Test-NonRoutableIp -Ip '100.64.0.5')  'cgnat low'
Assert-Equal 'cgnat'      (Test-NonRoutableIp -Ip '100.127.255.255') 'cgnat high'
Assert-Null  (Test-NonRoutableIp -Ip '100.128.0.0')              'past cgnat is public'
Assert-Equal 'multicast'  (Test-NonRoutableIp -Ip '224.0.0.1')   'v4 multicast'
Assert-Equal 'multicast'  (Test-NonRoutableIp -Ip 'ff02::1')     'v6 multicast'
Assert-Equal 'reserved'   (Test-NonRoutableIp -Ip '0.1.2.3')     '0/8 reserved'
Assert-Equal 'reserved'   (Test-NonRoutableIp -Ip '240.0.0.1')   '240/4 reserved'
Assert-Equal 'ula'        (Test-NonRoutableIp -Ip 'fd12:3456::1') 'v6 ULA'
Assert-Null  (Test-NonRoutableIp -Ip '8.8.8.8')                  'public v4'
Assert-Null  (Test-NonRoutableIp -Ip '2606:4700::1111')          'public v6'
Assert-Equal 'invalid'    (Test-NonRoutableIp -Ip 'nonsense')    'garbage flagged invalid (never treated as routable)'

# --- alternate spellings must not bypass the v4 classes (review finding) ---
Assert-Equal 'rfc1918'    (Test-NonRoutableIp -Ip '::ffff:10.0.0.1')     'v4-mapped private is rfc1918'
Assert-Equal 'loopback'   (Test-NonRoutableIp -Ip '::ffff:127.0.0.1')    'v4-mapped loopback'
Assert-Equal 'cgnat'      (Test-NonRoutableIp -Ip '::ffff:100.64.0.5')   'v4-mapped cgnat'
Assert-Equal 'rfc1918'    (Test-NonRoutableIp -Ip '167772161')           'decimal spelling of 10.0.0.1'
Assert-Equal 'tunnel'     (Test-NonRoutableIp -Ip '2001:0:4136:e378::1') 'teredo refused'
# embedded IPv4 is NOT judged here: a 6to4/NAT64 address wrapping 127.x or
# 169.254.x is a routable v6 destination, and 'loopback'/'link-local' would
# turn it into silent local-noise in classify (review finding)
Assert-Null  (Test-NonRoutableIp -Ip '2002:7f00:1::1')                   '6to4 wrapping 127.x is not loopback'
Assert-Null  (Test-NonRoutableIp -Ip '64:ff9b::a9fe:a9fe')               'NAT64 wrapping 169.254.x is not link-local'
Assert-Null  (Test-NonRoutableIp -Ip '64:ff9b::a00:1')                   'NAT64 wrapping rfc1918 judged by lookup guard only'
Assert-Equal 'reserved'   (Test-NonRoutableIp -Ip '::')                  'v6 unspecified'
Assert-Null  (Test-NonRoutableIp -Ip '::ffff:8.8.8.8')                   'v4-mapped public stays routable'
Assert-Null  (Test-NonRoutableIp -Ip '64:ff9b::808:808')                 'NAT64 public stays routable'

# --- ConvertTo-CanonicalIp / Get-EmbeddedIPv4 ---
Assert-Equal '10.0.0.1'      (ConvertTo-CanonicalIp -Ip '::ffff:10.0.0.1')   'mapped -> v4'
Assert-Equal '203.0.113.10'  (ConvertTo-CanonicalIp -Ip '3405803786')        'decimal -> dotted'
Assert-Equal '10.0.0.1'      (ConvertTo-CanonicalIp -Ip '0x0a000001')        'hex -> dotted'
Assert-Equal '2001:db8::1'   (ConvertTo-CanonicalIp -Ip '2001:db8::1%junk&x=y') 'scope/junk stripped'
Assert-Equal '2001:db8::1'   (ConvertTo-CanonicalIp -Ip '2001:DB8:0::1')     'v6 compressed lowercase'
Assert-Null  (ConvertTo-CanonicalIp -Ip 'nope')                               'garbage -> null'
Assert-Equal '10.0.0.1'      (Get-EmbeddedIPv4 -Ip '64:ff9b::a00:1')         'NAT64 embedded'
Assert-Equal '192.168.1.1'   (Get-EmbeddedIPv4 -Ip '2002:c0a8:101::')        '6to4 embedded'
Assert-Null  (Get-EmbeddedIPv4 -Ip '2606:4700::1111')                         'plain v6 embeds nothing'
Assert-Equal '10.0.0.1'      (Get-EmbeddedIPv4 -Ip '::ffff:0:a00:1')         'SIIT embedded'
Assert-Equal 'tunnel'        (Test-NonRoutableIp -Ip '64:ff9b:1::a00:1')     'local-use NAT64 never looked up'
Assert-Equal 'tunnel'        (Test-NonRoutableIp -Ip '64:ff9b:1:ff::1')      'local-use NAT64 whole /48'
Assert-Null  (Test-NonRoutableIp -Ip '64:ff9b:2::1')                          'just outside local-use /48'
Assert-Null  (Get-EmbeddedIPv4 -Ip '8.8.8.8')                                 'v4 embeds nothing'

# --- ConvertTo-CymruName ---
Assert-Equal '4.108.90.216.origin.asn.cymru.com' (ConvertTo-CymruName -Ip '216.90.108.4') 'v4 reversal'
$v6name = ConvertTo-CymruName -Ip '2001:db8::1'
Assert-True ($v6name -like '*.origin6.asn.cymru.com') 'v6 uses origin6 zone'
Assert-True ($v6name.StartsWith('1.0.0.0.')) 'v6 nibbles reversed (last nibble first)'
Assert-Null (ConvertTo-CymruName -Ip 'garbage') 'garbage yields null'

Complete-Tests
