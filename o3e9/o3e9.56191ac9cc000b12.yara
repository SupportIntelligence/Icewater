
rule o3e9_56191ac9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.56191ac9cc000b12"
     cluster="o3e9.56191ac9cc000b12"
     cluster_size="82"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock yvupbvli nabucur"
     md5_hashes="['01e42c5869769022772f0d863fc70edf','09d388003093b16ce5112db40581cf8b','a15421a414e1908105da9a457edbcccf']"

   strings:
      $hex_string = { f8d5b4fff5d3b3fff3d0b2fff0ceb0ffeecbafffeccaadffebc8acffe8c6aaffe5c3a9ffe3c1a7ffe2c0a6ffe0bea4ffddbba3ffdab9a2ffdeae8fc6dfac8514 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
