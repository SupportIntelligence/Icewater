
rule m2319_34bb1cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.34bb1cc1c4000932"
     cluster="m2319.34bb1cc1c4000932"
     cluster_size="110"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['937a1511579d729b5679ec5d2b7ccb94ecadfab5','1fca60329896c03caa655f689cbf4b07625e9fe5','a7d945c490447534b2f7e5cbad168e0414b1e571']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.34bb1cc1c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
