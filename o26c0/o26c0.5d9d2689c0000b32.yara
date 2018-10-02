
rule o26c0_5d9d2689c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.5d9d2689c0000b32"
     cluster="o26c0.5d9d2689c0000b32"
     cluster_size="435"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious filerepmalware genkryptik"
     md5_hashes="['354536c0359f23fea1d1eb0397e9b8260894a2dc','fdb4de874f249cc84ccdf55ac326a7b8696f2c99','595e2beab3884f1d0153443b8b4c549455902d38']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.5d9d2689c0000b32"

   strings:
      $hex_string = { 880e8d2c808b461003ed896e048bdd8a000fbef883ef300fafdf3c307c393c3a7d3585ff741a84c9752d83c8ff33d2f7f73bc572228b4e088bc3f7d03b017217 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
