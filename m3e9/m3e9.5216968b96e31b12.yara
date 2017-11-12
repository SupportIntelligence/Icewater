
rule m3e9_5216968b96e31b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5216968b96e31b12"
     cluster="m3e9.5216968b96e31b12"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="barys wbna vobfus"
     md5_hashes="['811c053880ea63afc93f1001f87c921a','853fa56b882b11eaefb876f0643a86df','f32dcddf1719755cfcbf1c41b9b86cdb']"

   strings:
      $hex_string = { 0183f22312f61bfe092bfe491271e74f85fab271be998d0a6f4b48dc804707e84d2431c21b41183e9a163cda609ae6224fa899a8e2bcf7d379ddd55127bd74fd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
