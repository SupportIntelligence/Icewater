
rule o26bb_638da12cdde30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.638da12cdde30912"
     cluster="o26bb.638da12cdde30912"
     cluster_size="110"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious adload"
     md5_hashes="['cb57f9fc65f263b82cd31fa2c88f872daf1d6781','51ffac09d878e81d4e8a0e97b7a21e365d1ebca4','80edcd214a2b2177a24afd6113b8b491074235d9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.638da12cdde30912"

   strings:
      $hex_string = { 03c13bd8772839461474236a01508bcee83cd6ffff84c07415895e10837e140872048b06eb028bc633c966890c5866833f00750433c9eb188bcf8d51020f1f40 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
