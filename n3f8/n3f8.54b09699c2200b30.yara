
rule n3f8_54b09699c2200b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.54b09699c2200b30"
     cluster="n3f8.54b09699c2200b30"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos ginamster clicker"
     md5_hashes="['89dd81231edc442504b23aee05bc64cface71f11','25af1a800de0cf6e64158b221a7f76e5bebd9608','3197aaab8dc276b4fd8e7261be48e699e41c9ee8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.54b09699c2200b30"

   strings:
      $hex_string = { 742f76342f6d656469612f4d6564696142726f77736572436f6d706174417069323124537562736372697074696f6e43616c6c6261636b50726f78793b00324c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
