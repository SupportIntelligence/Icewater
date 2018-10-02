
rule k2319_185696a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185696a9c8800b32"
     cluster="k2319.185696a9c8800b32"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['8b357c67833ee28aecd17ce64bc197933798e3ce','7dad5d183c2604ea7355ae8f24e7ab2972eda125','e55d09312085d8bfb9c5fdfb27ab2566cd2e4ae6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185696a9c8800b32"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e206f5b545d3b7d76617220643d28307846383c2835362c3078313136293f2831312e363545322c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
