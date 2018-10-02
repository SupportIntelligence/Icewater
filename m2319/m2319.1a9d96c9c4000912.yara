
rule m2319_1a9d96c9c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1a9d96c9c4000912"
     cluster="m2319.1a9d96c9c4000912"
     cluster_size="159"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['68916a7fd75bf461f73d759e9f4a034239c4bbba','27d6f4af295dd2861aebf1717a54d65230335fea','e361df0ca4f0e7a52edc1682dcf50550162a5074']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1a9d96c9c4000912"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
