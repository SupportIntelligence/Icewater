
rule k2319_1a151c99c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a151c99c2200b12"
     cluster="k2319.1a151c99c2200b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4a1f055a6de362369c2d724e3871e4f45e933e62','303482ce244bcb91f6af25bc78ab3d6e95911b8c','5fc472e32ed06e83e45cfac83d6628a97250ab5a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a151c99c2200b12"

   strings:
      $hex_string = { 6e646566696e6564297b72657475726e20545b565d3b7d76617220413d282831332e3545322c34332e34304531293c3d352e303745323f2833372c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
