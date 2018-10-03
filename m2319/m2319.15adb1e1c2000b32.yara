
rule m2319_15adb1e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.15adb1e1c2000b32"
     cluster="m2319.15adb1e1c2000b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script trojandownloader"
     md5_hashes="['10b29a3a5b887e5b0e6cdcd6dc69e1e2f8befb6d','2f3d85f380768eee5a0c57c7aa93bdefecff328c','d77b2fa39b8ba9c7aa2198dc8d2e2c80af2c8573']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.15adb1e1c2000b32"

   strings:
      $hex_string = { 3e3c6272202f3e0a0a0a3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
