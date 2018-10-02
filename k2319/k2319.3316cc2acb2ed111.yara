
rule k2319_3316cc2acb2ed111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3316cc2acb2ed111"
     cluster="k2319.3316cc2acb2ed111"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['781664cec96ce4ce9db2c5b8cf909d224753a2a0','4bf1749e72ec4473a8410e733919a41ceaacf5c5','6d0a5ef7846b1f8149a0ae3b69ea93b632acd36e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3316cc2acb2ed111"

   strings:
      $hex_string = { 6e646f773b666f72287661722051384420696e204a336d3844297b6966285138442e6c656e6774683d3d3d2828312e33333245332c30783137293e307845373f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
