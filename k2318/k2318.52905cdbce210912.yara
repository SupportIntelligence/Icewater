
rule k2318_52905cdbce210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52905cdbce210912"
     cluster="k2318.52905cdbce210912"
     cluster_size="1457"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['ad43a030f9d13be4f19dfff7cfbd64a8fb1d7566','4220f3870c77e2a2567b843c6d7ba0d85433d0b2','1306ea43addbbce7fa03944ea9400c2c2d5e862f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52905cdbce210912"

   strings:
      $hex_string = { d2e0e1ebe5f2eaf320eff0e8e9ece0fef2fc20efb3e420f7e0f120bfe6b32c20f0eee7f7e8ede8e2f8e820f320f1eaebffedf6b30d0a0d0ae2eee4e82e0d0a0d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
