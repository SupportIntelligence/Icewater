
rule m3f7_6314ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.6314ea48c0000b12"
     cluster="m3f7.6314ea48c0000b12"
     cluster_size="44"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['0bedd838421ff837b4713d18acb82860','11350a0827c242ce95d4bb0412719cb6','5182e868d917be3c2e403c2bb4bc53cb']"

   strings:
      $hex_string = { 6d656e7442794964282750726f66696c653127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
