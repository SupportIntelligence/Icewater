
rule m2319_1ad296c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1ad296c9c4000b12"
     cluster="m2319.1ad296c9c4000b12"
     cluster_size="624"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['7844c4fe09fb4cbe447768527c55233b035bb76e','94996ff14e66c5cdb1c5bce73320e5665384c367','e512da27e6da5c6ad0d403ca0ebc86c9ce6feab5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1ad296c9c4000b12"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
