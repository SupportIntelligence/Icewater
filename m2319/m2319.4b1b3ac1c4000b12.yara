
rule m2319_4b1b3ac1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4b1b3ac1c4000b12"
     cluster="m2319.4b1b3ac1c4000b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['2682a7dec132ede750e8966b5fcbe786','481168e775ba99f7db90f11b71b5bc9f','f6e417aba97c1850ab49f909c1798a0a']"

   strings:
      $hex_string = { 6d656e7442794964282750726f66696c653127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
