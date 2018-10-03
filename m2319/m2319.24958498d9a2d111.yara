
rule m2319_24958498d9a2d111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.24958498d9a2d111"
     cluster="m2319.24958498d9a2d111"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink script html"
     md5_hashes="['69b495fd1c7673a5d7fb4b621232b1b6e5926cef','cfae9a92d145b565bfa6cbb54eee006f06cb8fa8','0b55da1e9f5476fb0176d6594bbaf3ea6a1f0d52']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.24958498d9a2d111"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
