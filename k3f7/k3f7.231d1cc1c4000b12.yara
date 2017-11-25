
rule k3f7_231d1cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.231d1cc1c4000b12"
     cluster="k3f7.231d1cc1c4000b12"
     cluster_size="3"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script html infected"
     md5_hashes="['01ba475ebed6a8c1df5fced7820d6759','74294c63a09e983a1d7dbec1588b2009','91eb6874b0592c8624ce3f4445a0e6c8']"

   strings:
      $hex_string = { 3d200d0a2827303132333435363738394142434445464748494a4b4c4d4e4f5051525354555658595a6162636465666768696a6b6c6d6e6f7071727374757678 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
