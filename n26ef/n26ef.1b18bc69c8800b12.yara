
rule n26ef_1b18bc69c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26ef.1b18bc69c8800b12"
     cluster="n26ef.1b18bc69c8800b12"
     cluster_size="337"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer malicious miner"
     md5_hashes="['edf402b20a977c57192b72c9757ae758ca7ae489','43bec98c9adc561d5994b42182e5c4a2b70d87f6','80a89995f4b619c363ba05145f4b528e78b60ca0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26ef.1b18bc69c8800b12"

   strings:
      $hex_string = { 6b7c01894b58751a8bc124413c40751283e1bf894b58f6c1207407488b4308ff4808ff15616904008bc8e89adb00004863d0eb084585f67e0d4963d64c8d45c7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
