
rule m3e9_29d4e4c8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29d4e4c8c0000b32"
     cluster="m3e9.29d4e4c8c0000b32"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['14cbf3156775d2aa271887fbbfd0e9e1','22b0d90607b53ce091c67c7f23c0b642','da25078cbfeee392ebd3994778285b4b']"

   strings:
      $hex_string = { 5e65af057886827e3e484a4ea64330575b63af0b7d898b8a4d4b496a555138585c64af29888c8d926d313c3a53503b595d1705768f8e90948456473f0234376c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
