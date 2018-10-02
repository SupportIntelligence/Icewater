
rule k2319_511a82b9caa00b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.511a82b9caa00b32"
     cluster="k2319.511a82b9caa00b32"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['253b1c179335b6f636e6931dccd565804f7bcdf9','fe0122b556a364333c05b7ba0d9afea04986c6b0','d51ee1b309394ea75234416e3dcdcc378130331d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.511a82b9caa00b32"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e206c5b515d3b7d76617220453d282830783134432c32352e293c30783233443f2830783146382c3078636339 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
