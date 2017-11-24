
rule m2321_11b3255ad8bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.11b3255ad8bb0912"
     cluster="m2321.11b3255ad8bb0912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob shiz"
     md5_hashes="['180cb230f531c7f37743234b29552f27','6ef36348d62697de2bd3205ff681c8f2','df3bc6d687716cd66cfed2acdba582ee']"

   strings:
      $hex_string = { 7b4ed2b50f187ab604e072da21a9e120edcd30f82eaa1f6a7ddbbbd0a0fad376125cc2debb80b4aef258d4d90b9c1a43b02a7555f602c779d8d7073c168d34ca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
