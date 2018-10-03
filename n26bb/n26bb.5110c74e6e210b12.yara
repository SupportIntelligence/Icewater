
rule n26bb_5110c74e6e210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5110c74e6e210b12"
     cluster="n26bb.5110c74e6e210b12"
     cluster_size="70926"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadguide bundler unwanted"
     md5_hashes="['0ec0498bcb58815e51d35e8ba54a968117d8669d','b9ee2afa2aef2d1edd16e45edc0a57c709bf1b61','90c90c2531117daba5f7769ac8b66b2741ecbc83']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5110c74e6e210b12"

   strings:
      $hex_string = { c672ec6bc90c034d085e3bc17305395004740233c05dc3ff356c0f4800ff155cc14500c36a2068d0934700e8f780ffff33ff897de4897dd88b5d0883fb0b7f4b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
