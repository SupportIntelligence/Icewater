
rule o26d7_3914640080000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.3914640080000000"
     cluster="o26d7.3914640080000000"
     cluster_size="17945"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy attribute hacktool"
     md5_hashes="['dce3e8692feb3671613f8fc93516add03ea7c80c','f3fd6bfa64f6a6360f9976e5e214ad59015780aa','5cb1c9ab592dcfca5f65936a0b3b5cbada92f151']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.3914640080000000"

   strings:
      $hex_string = { 4e657874446c675461624974656d00df0253686f7757696e646f770000320377737072696e746641000900417070656e644d656e754100c40044726177466f63 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
