
rule m2319_1d0ab1e1c2000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.1d0ab1e1c2000932"
     cluster="m2319.1d0ab1e1c2000932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['2a0d32df3f585e4a33cf06e667d0049bedb2162a','9a675de4b521ee2791e152ee2dae091de6a50311','bfc14f1922166871df4516234f044d5870b8b100']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.1d0ab1e1c2000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
