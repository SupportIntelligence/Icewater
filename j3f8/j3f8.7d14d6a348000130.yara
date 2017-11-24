
rule j3f8_7d14d6a348000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7d14d6a348000130"
     cluster="j3f8.7d14d6a348000130"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['24d90b3791634615d52573d51b2ec69a','71326ff8dbb2745a46263139099245d4','c3165ebe5e255af587f7f6c7dbc5d1ea']"

   strings:
      $hex_string = { 616e672f436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e41637469766974795468726561640026 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
