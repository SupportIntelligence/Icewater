
rule n2319_031d6949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.031d6949c0000b12"
     cluster="n2319.031d6949c0000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clickjack"
     md5_hashes="['3b4fa3b29667bc21a42f8a5b74ea67fc486b6b9e','abb95a56bf3b8b475e91f07e5b27764b1ecbd963','3eb32f68a1809d65e6d8ac192bfa8e8a7760120e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.031d6949c0000b12"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
