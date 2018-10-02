
rule o26bb_3914640080000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.3914640080000000"
     cluster="o26bb.3914640080000000"
     cluster_size="18232"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious attribute"
     md5_hashes="['258b95c81eda7900ccd4fc6236ebdec67f470000','2d239ec124681a8b4107531b6c3d90af7bb8c12b','d816ad1e4dc03befa3a4ce58ef9c0dfa85c54065']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.3914640080000000"

   strings:
      $hex_string = { 4e657874446c675461624974656d00df0253686f7757696e646f770000320377737072696e746641000900417070656e644d656e754100c40044726177466f63 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
