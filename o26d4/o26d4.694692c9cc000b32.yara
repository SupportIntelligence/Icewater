
rule o26d4_694692c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.694692c9cc000b32"
     cluster="o26d4.694692c9cc000b32"
     cluster_size="82"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy gamehack malicious"
     md5_hashes="['e5650ef39383c44655bd72dd162dfedc92f485bd','4bc5c04478831b5527979ef851da4c9d623b4781','b85d51f840496d73b27624479e0c160c782d1dae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.694692c9cc000b32"

   strings:
      $hex_string = { bd005897bd00a09d3c00a09d3c0044013e0044013e00d89f3d00d89f3d00c0c5bc00c0c5bc0040a2bd0040a2bd00201ebe00201ebe00603fbe00603fbe00f0e7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
