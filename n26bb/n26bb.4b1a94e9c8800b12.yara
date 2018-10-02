
rule n26bb_4b1a94e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4b1a94e9c8800b12"
     cluster="n26bb.4b1a94e9c8800b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious heuristic"
     md5_hashes="['daa8f59c16cbf25df9deea952f9a8c23ac0b0137','1be67030f3d390896880b412861914df2b15fd3d','7701071963c389db516611e3e4282bc62f617e41']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4b1a94e9c8800b12"

   strings:
      $hex_string = { c7830a4f43c4c153cff6aebc2a07696573d59e2014074c3b74d8544dfccc64248fe4ba81a982da32841f0460d7155d44ea617db07601c3ecb177201c1f2fac15 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
