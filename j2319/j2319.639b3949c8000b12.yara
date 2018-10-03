
rule j2319_639b3949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.639b3949c8000b12"
     cluster="j2319.639b3949c8000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browsermodifier"
     md5_hashes="['c8b913b3ae3cc7814ce126a316a2697e3ca4e78c','f384c5a8b50eb272668d6581548d49e8501f1636','0c064fa3c699723f0089b077108027fbbcb4f588']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.639b3949c8000b12"

   strings:
      $hex_string = { 4a7a7928612e73636f6465293b7472797b76617220633d612e65706f63682d6d6e672e65706f636828293b333630303e63262673657454696d656f7574287379 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
