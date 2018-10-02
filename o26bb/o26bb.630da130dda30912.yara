
rule o26bb_630da130dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.630da130dda30912"
     cluster="o26bb.630da130dda30912"
     cluster_size="398"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious aeahd"
     md5_hashes="['7e032681c2f2a7c4750440c599a6cac38209663b','ed830df8b1d5aa310bf75f83368d75c12ea740a5','518a57636b92470c1737cf95a3b72e9f8d447afb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.630da130dda30912"

   strings:
      $hex_string = { 687dfe7f00895618e80b25fdff8b550883c45c8b5e18803a00750433c9eb138bca578d79010f1f008a014184c075f92bcf5f51528d4b08e86c50feff68290e65 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
