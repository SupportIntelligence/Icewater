
rule j2319_72959ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2319.72959ec1c8000b12"
     cluster="j2319.72959ec1c8000b12"
     cluster_size="48"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script diplugem"
     md5_hashes="['7e693ea303407d275c1c4cfe4e787c3787615fd9','af833da7caa1084c447b73a8b185bd18ed285a8b','d862571f7d682532bc8cdbb8f9f3259e955fe2d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2319.72959ec1c8000b12"

   strings:
      $hex_string = { 4a7a7928612e73636f6465293b7472797b76617220633d612e65706f63682d6d6e672e65706f636828293b333630303e63262673657454696d656f7574287379 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
