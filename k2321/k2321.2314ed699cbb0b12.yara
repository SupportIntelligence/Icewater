
rule k2321_2314ed699cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2314ed699cbb0b12"
     cluster="k2321.2314ed699cbb0b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="emotet tinba vbkrypt"
     md5_hashes="['175cba45604dd898fad562cb213ff8b3','24b3b41db2080ad80d8f8cda05c47806','f94f51e1bdaf0e8af45380bc90745beb']"

   strings:
      $hex_string = { 6324c7017c0ee9fd46a88a1122608419a61f35762af41db93622e7b8806f0fcd2dadfb314c27b2e84dc9d6dbc89b8d30bd699ad06c75cf902f47e36e0a812ca1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
