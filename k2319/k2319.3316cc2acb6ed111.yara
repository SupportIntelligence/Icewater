
rule k2319_3316cc2acb6ed111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3316cc2acb6ed111"
     cluster="k2319.3316cc2acb6ed111"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['a38ebab787b522f8c79e8824766d6aae6aa34416','868dc1ff39bc688cb3fa07fc8c5b646fc5960441','98041854700ca507222210e571a8b8c891ff7cdf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3316cc2acb6ed111"

   strings:
      $hex_string = { 6e646f773b666f72287661722051384420696e204a336d3844297b6966285138442e6c656e6774683d3d3d2828312e33333245332c30783137293e307845373f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
