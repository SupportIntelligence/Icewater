
rule j3e7_7114d6c348000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7114d6c348000310"
     cluster="j3e7.7114d6c348000310"
     cluster_size="18"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos revo"
     md5_hashes="['1100d03703f2dcd7d9e2da2f255b136e','1af37ef819163b7a294eca4cf0cd42ad','f2abe50edd04c08da359fa2f7b30feda']"

   strings:
      $hex_string = { 6e672f436c6173734c6f616465723b00154c6a6176612f6c616e672f457863657074696f6e3b00124c6a6176612f6c616e672f4f626a6563743b00124c6a6176 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
