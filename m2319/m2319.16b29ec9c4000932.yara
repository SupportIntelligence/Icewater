
rule m2319_16b29ec9c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.16b29ec9c4000932"
     cluster="m2319.16b29ec9c4000932"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery trojandownloader classic"
     md5_hashes="['823ab904621a61c96ee3774d6a0995e9f9c1d3e2','05afc900a6ecb1283ce722230fa1863ff66e3bea','b74c1fc0f771e077c896dca44240ae4b2973887e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.16b29ec9c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
