
rule m2321_2b1db099c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b1db099c2200b32"
     cluster="m2321.2b1db099c2200b32"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['4b138a1d5372d5a2d3f5756caccaa690','6b59469efddfd8e4ef7bcf03585ae800','e58e9f3f7ffcb6728daabe1d0f72132d']"

   strings:
      $hex_string = { 0300cea74f3601e645b48297d6f583550df9e81b526aa621eac69518edb1d2b68012bc72687c4bf074470acd9863fa376e43cba3235d6f784206819f4490777f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
