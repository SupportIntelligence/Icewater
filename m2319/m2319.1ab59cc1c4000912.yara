
rule m2319_1ab59cc1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1ab59cc1c4000912"
     cluster="m2319.1ab59cc1c4000912"
     cluster_size="134"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['8d5ddf2f1f383996615444cf34b8367584de1044','67ca93857f5616c1b6376c0a37191865e14766e4','9e08c02dfb9a6cad199f96f65adb9383f416ce5b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1ab59cc1c4000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
