
rule j3f8_7194d6c3c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7194d6c3c8000330"
     cluster="j3f8.7194d6c3c8000330"
     cluster_size="91"
     filetype = "Dalvik dex file version 035"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['02d81985b733218ea9d78c6a39f70b8e','04ee0cc937039252ab1d9ac7c749b4ba','2b903feefbff45ad86e64d1c8810b8a6']"

   strings:
      $hex_string = { 6e672f436c6173734c6f616465723b00154c6a6176612f6c616e672f457863657074696f6e3b00124c6a6176612f6c616e672f4f626a6563743b00124c6a6176 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
