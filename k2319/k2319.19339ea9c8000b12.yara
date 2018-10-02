
rule k2319_19339ea9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.19339ea9c8000b12"
     cluster="k2319.19339ea9c8000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['388cf37a7ee7e0336a396df663719bf496ac83a9','a2d366d01e03b3a787ee67a7b9d07c231f76d933','20328c3a7b1b7e5f63845fa3a0a0ca4669d261b9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.19339ea9c8000b12"

   strings:
      $hex_string = { 5b505d213d3d756e646566696e6564297b72657475726e20765b505d3b7d76617220443d28283078362c313335293e3d35342e3f28342e313945322c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
