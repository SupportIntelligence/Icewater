
rule j3f8_7d14d6e348000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7d14d6e348000130"
     cluster="j3f8.7d14d6e348000130"
     cluster_size="19"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['06e44418a2171c2e156344c5c5b9465e','0dc33f7ae02cb078cb5177629c3d2bfc','f08296d87ada29dfd5c47b4884e76c3f']"

   strings:
      $hex_string = { 672f436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e41637469766974795468726561640026616e }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
