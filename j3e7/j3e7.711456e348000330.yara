
rule j3e7_711456e348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.711456e348000330"
     cluster="j3e7.711456e348000330"
     cluster_size="20"
     filetype = "Dalvik dex file version 035"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['2688ddbdc75f2ed7c6fb9b81ddbb1cf2','26932c102f39427f4946460a284589be','df694e41cddfe69e31abed67e5d1ffc8']"

   strings:
      $hex_string = { 436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e41637469766974795468726561640026616e6472 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
