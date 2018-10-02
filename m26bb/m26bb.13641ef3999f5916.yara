
rule m26bb_13641ef3999f5916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.13641ef3999f5916"
     cluster="m26bb.13641ef3999f5916"
     cluster_size="83"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious installcore attribute"
     md5_hashes="['5af2934307eb10acb1dc72fe9fde8360ab61f13e','634efa4f3db8bbe505c18346c20fcd4c00687c01','f0a6afa219e60c03458567d359c8e634305a096c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.13641ef3999f5916"

   strings:
      $hex_string = { 7c24083bfb761e6a0468001000002bfb5753e826fcffff85c0750a8b44240433d28910eb0a8b3681fe3cc4400075bc83c40c5d5f5e5bc38bc053565755518bd8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
