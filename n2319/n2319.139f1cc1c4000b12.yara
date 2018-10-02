
rule n2319_139f1cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.139f1cc1c4000b12"
     cluster="n2319.139f1cc1c4000b12"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clicker"
     md5_hashes="['e67c17330b099b313ba1a080adc568d7dd60c47e','2595d6bb1a5c3692e7a696eb026a919f1b006acc','55c651372d5a22d7d82ee3468dc4af4e8423a58c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.139f1cc1c4000b12"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
