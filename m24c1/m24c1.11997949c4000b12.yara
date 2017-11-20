
rule m24c1_11997949c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c1.11997949c4000b12"
     cluster="m24c1.11997949c4000b12"
     cluster_size="5"
     filetype = "Dalvik dex file version 035 (Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="triada androidos appad"
     md5_hashes="['385296435f0f97158def755260f70730','3ff30ea59705d41ea389f256468b6bcb','de06746d965cc93efaabae544d45f0b0']"

   strings:
      $hex_string = { d160fa1f811a2d658f716907789dd0a3241e5e178c479a0d94239746f0764ed626f4feb586aff71fdd45ef9f73b6c1ea10352b28ded2bb01a5c440cdbc9ea436 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
