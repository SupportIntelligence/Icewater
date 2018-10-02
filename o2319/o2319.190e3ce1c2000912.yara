
rule o2319_190e3ce1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.190e3ce1c2000912"
     cluster="o2319.190e3ce1c2000912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer coinhive"
     md5_hashes="['14b87a4a49c101da8045e4866d9b9c28f82cf56e','760997705b5e3ef6359edf671bdc2e2a335403a4','5edd616be56e81170b31cca398df7c3e98506daf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.190e3ce1c2000912"

   strings:
      $hex_string = { 21302c206e616d653a2022464c4f57455220504c4159494e47204341524453222c2073686f72745f6e616d653a2022666c6f7765725f706c6179696e675f6361 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
