
rule n2319_43992949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.43992949c0000b12"
     cluster="n2319.43992949c0000b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker script"
     md5_hashes="['36c72f6ee5aa7491048123890e878baa12e8c002','24224fdae4cafb4fc0ba18942c7d7b5d39bb6a6b','52014ab3ab66f19dd39e7984b5b1ccb71b4dbf86']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.43992949c0000b12"

   strings:
      $hex_string = { 5d2a295c732a5c5d2f672c223d272431275d22293b696628216b2e6973584d4c286129297472797b696628657c7c216c2e6d617463682e50534555444f2e7465 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
