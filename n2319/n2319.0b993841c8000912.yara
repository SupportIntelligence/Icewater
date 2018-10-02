
rule n2319_0b993841c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.0b993841c8000912"
     cluster="n2319.0b993841c8000912"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack script clickjack"
     md5_hashes="['1cd9e759444c36f0a5ed2c74e8a00a9411fdd3a9','9fec22331d1a8f39390eb67ae23bac71df8f2a47','3ffd331416e09ec1f030bad2be9116faf3dba45a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.0b993841c8000912"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
