
rule m2319_12b79cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.12b79cc1c4000932"
     cluster="m2319.12b79cc1c4000932"
     cluster_size="182"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['a842acd48c7c8e7148cc9a3909288cd092129d39','e9e0359379c4d38003360282f7292a55252f4ea2','18a416247c872f4c8794ccf0f6e0c95a794d661f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.12b79cc1c4000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
