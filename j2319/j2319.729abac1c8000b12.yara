
rule j2319_729abac1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.729abac1c8000b12"
     cluster="j2319.729abac1c8000b12"
     cluster_size="101"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browsermodifier"
     md5_hashes="['0e767035c60c75595be131967cfc05f87b4e6f38','b9adfe0128cf95dafa4e91ff0476ec083eada479','bf68b38e60d8ed8c8dddb6903d2f58e8d48c2966']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.729abac1c8000b12"

   strings:
      $hex_string = { 4a7a7928612e73636f6465293b7472797b76617220633d612e65706f63682d6d6e672e65706f636828293b333630303e63262673657454696d656f7574287379 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
