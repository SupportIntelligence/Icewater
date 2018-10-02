
rule o26bb_6919390140000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6919390140000110"
     cluster="o26bb.6919390140000110"
     cluster_size="4670"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zusy malicious adposhel"
     md5_hashes="['f8acbf2f0a8d280126e2209b7b2a71ce9244be15','5916434497335e8e6835687bbc06bede7dbd299b','5c9e4893955e43fceb6e1145010c713e9ad9eee1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6919390140000110"

   strings:
      $hex_string = { 7665506f70757000001d01476574437572736f72009400446566446c6750726f63410022024f656d546f4368617242756666410000fb00466c61736857696e64 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
