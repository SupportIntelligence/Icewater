
rule k3f8_6966684540000114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.6966684540000114"
     cluster="k3f8.6966684540000114"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smforw androidos trojansms"
     md5_hashes="['7684c7a008fd3cf0610ca4ad0a4153e921f3eb10','19e944fcdd204458b1e056f5b7613a0ae3b0971e','24d3576fcaa4a390372d4518da42758d17c0cb74']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.6966684540000114"

   strings:
      $hex_string = { 7057040041652202100070101d000200220425006e106c000a000c051506037f7030440054065b140200714005008a820c035b130100130464006e3073004a01 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
