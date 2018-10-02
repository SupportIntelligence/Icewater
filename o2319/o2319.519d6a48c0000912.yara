
rule o2319_519d6a48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.519d6a48c0000912"
     cluster="o2319.519d6a48c0000912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos coinminer miner"
     md5_hashes="['c37c6c8ac4e36a61a77c31edb2944d16204fe277','38d90e7420535543f90325ddcdf0ca9b1fa37ad8','d5f19204cbd3f9f5870680c6695d43bd65f6e7a6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.519d6a48c0000912"

   strings:
      $hex_string = { 74696f6e2861297b72657475726e20613f612e7265706c616365282f5b21222425262728292a2b2c2e5c2f3a3b3c3d3e3f405c5b5c5d5c5e607b7c7d7e5d2f67 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
