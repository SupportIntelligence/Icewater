
rule o26bb_6384a0b4dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6384a0b4dda30912"
     cluster="o26bb.6384a0b4dda30912"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['6436c684d210da96e651022ad0895902d0437dfc','52d59b5d67ec8ef4987e5d7af16c8716e0c1cd5c','b4febe8431b1f32f6e9033d34ced12ae4ded2f86']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6384a0b4dda30912"

   strings:
      $hex_string = { d9c1c30e03da8bcef7d18bc323c623ca0bc88bc281c1ed145a45034ddc03f98bcaf7d1c1cf0c23cb8d9605e9e3a98b75b803fb23c7897db00bc881c6f8a3effc }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
