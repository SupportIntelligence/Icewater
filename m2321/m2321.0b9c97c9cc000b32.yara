
rule m2321_0b9c97c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0b9c97c9cc000b32"
     cluster="m2321.0b9c97c9cc000b32"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['335394bc5d8f913f88241fe4e343405f','972fd63e94aa0ac6766ee6aa4eceb3b0','d5b23e431e734f087a10135f643629f4']"

   strings:
      $hex_string = { f651b33b63041d5231e366a90728125a5bcaa1f8d13aefa6a2650a2ad63516e5f5d0abc96e0c4eeb408f3c8143dd983e5cb42c77454b89c4ee1fcbc0d2cecdc8 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
