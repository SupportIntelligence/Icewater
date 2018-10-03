
rule n26d5_2595d69b613943af
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2595d69b613943af"
     cluster="n26d5.2595d69b613943af"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['faafe26f33cd3cefecff62b7b6932cdd78d9837a','156df2512194e35af05531fde5f3af700ba6cf3d','0ff822acd9a972d855588453287ed4bf1fc06d8a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2595d69b613943af"

   strings:
      $hex_string = { 7c9fb1c91946c7c6585bba4dadb6cbf31ff838f55a8d9b37aed2edb42957ca04cd1631111b7b75a377a763823024922ae1400862a1b326a456bf4fd191742268 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
