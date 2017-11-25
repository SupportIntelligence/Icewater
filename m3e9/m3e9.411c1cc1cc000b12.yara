
rule m3e9_411c1cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c1cc1cc000b12"
     cluster="m3e9.411c1cc1cc000b12"
     cluster_size="87"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack virut"
     md5_hashes="['0283cf2109de17a7c48caa067d016ef3','09c9f5a213fe2f90ec350ab586318c25','6831bd44d3fea31f24429b5a81f40053']"

   strings:
      $hex_string = { 073d58e5ad3b88c1e70c8b72fe451a41a413a78a1ec8bed4ffc97b1dc250f96bb0da4cbd623c9e9247a6cbbb5ab41f9adc5e3b8ef7e20e208fe10b6a5267dd00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
