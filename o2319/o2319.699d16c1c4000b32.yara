
rule o2319_699d16c1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.699d16c1c4000b32"
     cluster="o2319.699d16c1c4000b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['71945aa9c31930261eaa3292f5c8ae360066cb5d','bcdbeca734cce2130f674b81c38907f4e45b05f2','9493e01db68b33333ae1aa1ae197bbac56501e22']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.699d16c1c4000b32"

   strings:
      $hex_string = { 72696e67223d3d747970656f6620632626655b635d28297d297d622e56455253494f4e3d22332e332e37222c622e44454641554c54533d7b6f66667365743a31 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
