
rule m3e9_290f07a9c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.290f07a9c2000b32"
     cluster="m3e9.290f07a9c2000b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0cd9b97b116679cd672b7d95d3dbc946','2171cc071411a332fc01d410cf6f6f73','c90a60cee9501156516078d50c147203']"

   strings:
      $hex_string = { 00c652b18ecc539dac9167dfad27ab04f1a0822c967dc087aa1db6b29bf9b924134006cdea3657eee655977f07e24d11aec9a90c8d6ade53b5c222ed666f548f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
