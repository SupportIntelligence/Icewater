
rule n26ef_1b1c96b3c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26ef.1b1c96b3c6220b12"
     cluster="n26ef.1b1c96b3c6220b12"
     cluster_size="701"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner malicious"
     md5_hashes="['56eff5e3c3e7358beaf10fbb3a7079fd907d411f','64342e0028866766d5fa1e99b85bb25b3d18d147','a60674a6a88a217d1762b2d505f3f0df7c07f4ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26ef.1b1c96b3c6220b12"

   strings:
      $hex_string = { 6b7c01894b58751a8bc124413c40751283e1bf894b58f6c1207407488b4308ff4808ff1561c905008bc8e89adb00004863d0eb084585f67e0d4963d64c8d45c7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
