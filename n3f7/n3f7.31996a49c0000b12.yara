
rule n3f7_31996a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.31996a49c0000b12"
     cluster="n3f7.31996a49c0000b12"
     cluster_size="29"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker html"
     md5_hashes="['069acde019a2238c8689dcdfdd839f11','0d7ba5c84cc16126c4dd3ca63268d2c1','8e0bd9c79de7a71791e6944b81bc3e6a']"

   strings:
      $hex_string = { 6c2c20646f63756d656e742e676574456c656d656e7442794964282748544d4c3427292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f57 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
