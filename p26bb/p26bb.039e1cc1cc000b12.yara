
rule p26bb_039e1cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26bb.039e1cc1cc000b12"
     cluster="p26bb.039e1cc1cc000b12"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virlock nabucur polyransom"
     md5_hashes="['2e03371bda912a85ddf390646c20fa549b5e48b1','b04d29aed1c7aea9f05274654f20bc985e66b5b3','d191ae3a958a3349c8ac704615524bc968503498']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26bb.039e1cc1cc000b12"

   strings:
      $hex_string = { 0029292903c3c8cc7ba46d58ffc33c04ffc4591effca6426ffd06a25ffd37230ffe29d73fff1c6aeffecdfd6ffc9eef6ff9fe5f5ff5fceeaff39c3e5ff56cde7 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
