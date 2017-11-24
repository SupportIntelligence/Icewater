
rule m2321_32955eb9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.32955eb9c9800b16"
     cluster="m2321.32955eb9c9800b16"
     cluster_size="22"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['0b80ea128649df6a4a241074ad5b6f26','2d45bf0e67763b7cf9a93ce6686a937e','cf30f7215b004df42bbc8729138d2fb6']"

   strings:
      $hex_string = { d592a5f08586b367af5cbefcfbefbf6b7952ae3ccfdf7f6f696efa60c78e35ab564dcbcd1d1413ad0a09065b745482d07b2a6522e2b0476808048d4a1f36a7ba }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
