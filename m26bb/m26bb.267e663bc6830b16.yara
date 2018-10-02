
rule m26bb_267e663bc6830b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.267e663bc6830b16"
     cluster="m26bb.267e663bc6830b16"
     cluster_size="461"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="heuristic malicious adposhel"
     md5_hashes="['a2b1531a36b5bc9f5a72f0b2a0b383654434a291','043757eb03e1b7b99b40534d6ff57f9ed71256ff','5b946af808e9cb51785fde8e1fb5c1f1c421dcc6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.267e663bc6830b16"

   strings:
      $hex_string = { fa4b73f1d1672f97bb404775a8e39084c54834e4ec1d3019550ba50fc18b5d87e1ef4a385b329172dc43002a22d44c0a068a1ac33a3e175770201579b0c4b3cf }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
