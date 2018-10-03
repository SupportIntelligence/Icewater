
rule m2319_1d59b3a1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1d59b3a1c2000932"
     cluster="m2319.1d59b3a1c2000932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['cf7816f824400177b2e043da4dc0c9d1bd3dedfd','4517421ab43916adbb26f391a4fd2bc07ec0b231','24709fe8e326fc24c4bc92641d70c05a381b4255']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1d59b3a1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
