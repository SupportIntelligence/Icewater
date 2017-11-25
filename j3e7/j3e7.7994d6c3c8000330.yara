
rule j3e7_7994d6c3c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7994d6c3c8000330"
     cluster="j3e7.7994d6c3c8000330"
     cluster_size="407"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['01ccfb020d236bf20dd93d5edf0d5b02','0296b24b84d9b044ece1fbf10ab57a2b','0b8fbe01f232aa7cf92f3b252e27ce93']"

   strings:
      $hex_string = { 6e672f436c6173734c6f616465723b00154c6a6176612f6c616e672f457863657074696f6e3b00124c6a6176612f6c616e672f4f626a6563743b00124c6a6176 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
