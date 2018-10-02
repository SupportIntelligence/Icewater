
rule o26c0_5996ea4cc0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.5996ea4cc0000b12"
     cluster="o26c0.5996ea4cc0000b12"
     cluster_size="45"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bundler istartsurf malicious"
     md5_hashes="['cea6a15c294c5b847aa19f6a5b9d813fc39c8f41','b5f59e6d11ca01130490eb5a9e26d20918d404c0','5503652339914eec074a663f7cca201cd75d585f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.5996ea4cc0000b12"

   strings:
      $hex_string = { 8d46185750e8d4cfffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
