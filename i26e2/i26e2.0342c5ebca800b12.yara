
rule i26e2_0342c5ebca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26e2.0342c5ebca800b12"
     cluster="i26e2.0342c5ebca800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dorkbot winlnk jenxcus"
     md5_hashes="['92b2bb4379e0497c4aadd179668bee512ca54c10','58d286d05bd4533fede7318f12b6364c2511b74d','5ef2e2633e72b4a28ba217a5c29e59b6205a2e87']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26e2.0342c5ebca800b12"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c000000000000000000000000000000000000003c0031000000000000000000100077696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
