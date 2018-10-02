
rule m2319_14b29cc1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.14b29cc1c8000932"
     cluster="m2319.14b29cc1c8000932"
     cluster_size="65"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['909f1bb884e031827df6f203d8479d568609089d','93a01a49e38b5642779e8eeaad035f9d58b5ffd8','5abc84586a9ff038609436f6e11eb0244a81fccc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.14b29cc1c8000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
