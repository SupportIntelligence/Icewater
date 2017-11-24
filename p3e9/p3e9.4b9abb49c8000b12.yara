
rule p3e9_4b9abb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.4b9abb49c8000b12"
     cluster="p3e9.4b9abb49c8000b12"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['0ff556b184d615f68b3e98b2b48b1fb6','2dd2c755ba79b461eb282e7d20e830eb','cc5fc1a7461bba200a81d41631e4215a']"

   strings:
      $hex_string = { 0029292903c3c8cc7ba46d58ffc33c04ffc4591effca6426ffd06a25ffd37230ffe29d73fff1c6aeffecdfd6ffc9eef6ff9fe5f5ff5fceeaff39c3e5ff56cde7 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
