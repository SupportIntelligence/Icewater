
rule j3f8_7c14d6a348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7c14d6a348000330"
     cluster="j3f8.7c14d6a348000330"
     cluster_size="18"
     filetype = "Dalvik dex file version 035"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['0ecdff832fafc5a3d1ffc463f49a08d1','1bbcbc69e766bcdb9486f0bd5cbb9a5f','d8eef497c13e3d5856e4fed22e731edd']"

   strings:
      $hex_string = { 616e672f436c6173733b00135b4c6a6176612f6c616e672f4f626a6563743b000161001a616e64726f69642e6170702e41637469766974795468726561640026 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
