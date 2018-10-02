
rule n2319_51193841c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.51193841c8000b32"
     cluster="n2319.51193841c8000b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker autolike clicker"
     md5_hashes="['eb1acdff2a0076c793ad691d96fe1af82fcba85b','f7534b67f570493d7d62ef453f78a9d507023ce8','3605d827c28f633c3bc44d54803ca0be542f3ba9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.51193841c8000b32"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
