
rule m2319_150ab5a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.150ab5a1c2000932"
     cluster="m2319.150ab5a1c2000932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['2a43f18486e58351e1e77fd783bee4d043a960f2','af4d3719410bc39b2db848843c59b74af820f6c6','71271bb5b1ea8e471776e05f58ef4072cbef6b0d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.150ab5a1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
