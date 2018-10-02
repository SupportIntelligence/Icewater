
rule k2319_18561ab9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18561ab9c8800912"
     cluster="k2319.18561ab9c8800912"
     cluster_size="96"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['742511e58f86977fbcfa7179c9c80fd61c5b9ddf','e1b9bb9dc4ddb14bbbe4442f95b39bdff007ce22','8e24d5358a58e2ce0082294b1551fdc3cfe509f8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18561ab9c8800912"

   strings:
      $hex_string = { 3f2838352e2c313139293a2830783133302c3078323144292929627265616b7d3b766172204b347938753d7b2762304a273a226e222c274f364a273a226d4322 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
