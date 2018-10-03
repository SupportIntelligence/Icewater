
rule ofc8_4993264bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.4993264bc6220b12"
     cluster="ofc8.4993264bc6220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['daba15a91a71ca8277f969676b5ddbe8b77023d1','fd6339f4f9585d32f1ba0a1c94ed6b8adae91211','eca4b793332d08ad861146b7a3fb865d6d54c25b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.4993264bc6220b12"

   strings:
      $hex_string = { b42e039d89c6bc066368b2f67d0c3f671f7fe55fd8a539f0080152d77142e8ff5d1d98e6ad84ac005693e3cdd4dc541559328c30b16f23384533bb75d1a1777e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
