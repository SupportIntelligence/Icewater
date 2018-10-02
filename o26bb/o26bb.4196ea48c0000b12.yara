
rule o26bb_4196ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4196ea48c0000b12"
     cluster="o26bb.4196ea48c0000b12"
     cluster_size="452"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="floxif pioneer malicious"
     md5_hashes="['504327f2a9ebd2f23614f9b178b79e6cbaece439','8d9376f09daa65a2ea05eaaf5ee447fc5283bf1d','f6886ac8caac588576047423affddbb39bec50ef']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4196ea48c0000b12"

   strings:
      $hex_string = { c410893594dd4100b0015e8be55dc3b001c38bff53568bf15733ff8d46048bd02bd683c203c1ea023bc61bdbf7d323da74298b0683c9fff00fc1087516813e50 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
