
rule m2319_35bb7ac1c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.35bb7ac1c8000932"
     cluster="m2319.35bb7ac1c8000932"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['93a640bd77f4db8dbd95c22d8bacafac49fefe18','0fe623fce3a38cf06dcd80f49bf8b45631165b21','7961786d8c03eac279a23974912f2e01e64dc431']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.35bb7ac1c8000932"

   strings:
      $hex_string = { 746d702f696e7374616c6c5f346466653566333565633333362f64756d702e70687029205b3c6120687265663d2766756e6374696f6e2e696e636c756465273e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
