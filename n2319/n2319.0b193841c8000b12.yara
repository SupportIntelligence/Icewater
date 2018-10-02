
rule n2319_0b193841c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.0b193841c8000b12"
     cluster="n2319.0b193841c8000b12"
     cluster_size="42"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack script clicker"
     md5_hashes="['2866352f4712565242973bbcc8ba38956c8bc2d7','77e906b019fd6f458395d95c6f8ce1294e1a22ea','db1990ad0cc6e9f57beb5e698a1647685d1f9951']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.0b193841c8000b12"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
