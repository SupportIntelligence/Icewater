
rule o3e9_691d6a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.691d6a48c0000932"
     cluster="o3e9.691d6a48c0000932"
     cluster_size="31"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur gena"
     md5_hashes="['257d9b23849743db520e7a1f310466e3','5bdaa7f3be1f1bb63b64e3a6d1aac9d6','b79571494dbb4a06fddb86f7b0d45542']"

   strings:
      $hex_string = { 0029292903c3c8cc7ba46d58ffc33c04ffc4591effca6426ffd06a25ffd37230ffe29d73fff1c6aeffecdfd6ffc9eef6ff9fe5f5ff5fceeaff39c3e5ff56cde7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
