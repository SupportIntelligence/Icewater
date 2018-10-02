
rule m2319_1a959cc1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1a959cc1c4000912"
     cluster="m2319.1a959cc1c4000912"
     cluster_size="248"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['22281b494c252cbd90070678081a3253046b7473','0851e70a7668a5be50b82c9d3ab642d732a187c7','b8a2784d69aed6db2f4e23f07dd67da59de875ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1a959cc1c4000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
