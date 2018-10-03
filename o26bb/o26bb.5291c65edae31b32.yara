
rule o26bb_5291c65edae31b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.5291c65edae31b32"
     cluster="o26bb.5291c65edae31b32"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linkury zusy malicious"
     md5_hashes="['5356942a608912bb9a200bd4a8ca75d8fae46a79','80e7ad303c48e1bc98709a196ba68f12ef04ba32','840e6a283d8f1cebc98c5e242167d31bc8303121']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.5291c65edae31b32"

   strings:
      $hex_string = { cf8945cce8fee9ffff83c4048b55f885d274328a5f1380fb08732a0fb677198d879800000033c985f67e0d39500c741c4183c0143bce7cf30fb6c38994876001 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
