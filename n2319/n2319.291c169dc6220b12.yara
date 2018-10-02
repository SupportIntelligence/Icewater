
rule n2319_291c169dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.291c169dc6220b12"
     cluster="n2319.291c169dc6220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script faceliker clickjack"
     md5_hashes="['dad8a9c3a7d3eab9ba7f6d6a0319f04e4bc6a4c1','f4080f4dad3bff3c6f7b68d10a01f3f38833db19','d3e2de31239428e4df5f932872b8142755dd4545']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.291c169dc6220b12"

   strings:
      $hex_string = { 2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e746573 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
