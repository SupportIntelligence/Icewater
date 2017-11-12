
rule m3e9_691f84a6ded31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f84a6ded31912"
     cluster="m3e9.691f84a6ded31912"
     cluster_size="1012"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['00ae4fb0caacf39fce0f859f05eb7a3e','00ebe9e8d507f6d25fbc690bf62ad4b5','0c9b37a1dc90d629302c5d54c99cba0d']"

   strings:
      $hex_string = { 4343e3d59d07321c3c7a197ab08dcffcbf372b4eccfa35c9c757e25b3d540ddc5404c7b92fb6270561cabc8f12f345b2aa06936afb0ebdb20ea27cfb5cdb8c56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
