
rule o26bb_36b952e76d408914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.36b952e76d408914"
     cluster="o26bb.36b952e76d408914"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler malicious heuristic"
     md5_hashes="['f211695277962e5f23fdb04fe70a4d3432ea25b5','3872a0dac5413b952b9a0f95cb5de9362ac277f0','9a42dd4f98071c868dd0f10ef6120c43131b4b60']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.36b952e76d408914"

   strings:
      $hex_string = { 8d46185750e881c1ffff895e0483c40c33db89be1c02000043395de8764f807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
