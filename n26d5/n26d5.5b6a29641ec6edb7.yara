
rule n26d5_5b6a29641ec6edb7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5b6a29641ec6edb7"
     cluster="n26d5.5b6a29641ec6edb7"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy genx kryptik"
     md5_hashes="['c0e7c7f27680602b3a70d7c679a7ff820f8a602e','3f31b4682f120148e919e825e8ade2c982de58d5','52b9e61fc2b10e1f18d698730b0783db0e47f2e8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5b6a29641ec6edb7"

   strings:
      $hex_string = { 7c9fb1c91946c7c6585bba4dadb6cbf31ff838f55a8d9b37aed2edb42957ca04cd1631111b7b75a377a763823024922ae1400862a1b326a456bf4fd191742268 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
