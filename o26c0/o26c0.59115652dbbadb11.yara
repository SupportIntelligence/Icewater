
rule o26c0_59115652dbbadb11
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.59115652dbbadb11"
     cluster="o26c0.59115652dbbadb11"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi kryptik malicious"
     md5_hashes="['c5d5f514e3ab0dfd9dd3a529504019f5748a3644','531efddac54dede74fe0cbc4d5a51796e4b2da82','2eb12124c155c9f51e3bac56302d0263cfc80a3f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.59115652dbbadb11"

   strings:
      $hex_string = { 3b0f4dd257966d65989b6fcf9d74e9331755f92cc83f0e097ecb322304bccd9235bd20ad7691c20c7d4ad339d65fc18be556411014cc1b6afde789c96cf1a636 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
