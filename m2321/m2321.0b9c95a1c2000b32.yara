
rule m2321_0b9c95a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b9c95a1c2000b32"
     cluster="m2321.0b9c95a1c2000b32"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['280f70765827c9c4ad01d06c2f33a60e','7d91c5ac889baa352265cb5dcf7bc2b3','c276697d88192917e49581d3bd209773']"

   strings:
      $hex_string = { 7a11a046f379f2a6578db964323cddc57b4af017512b658c6abe88df547cbf6b90fb4e93bb74e5c3b05e687f8bcee0accfff23f4ef890b12f969e31ee829365f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
