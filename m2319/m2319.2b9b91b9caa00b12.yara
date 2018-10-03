
rule m2319_2b9b91b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b9b91b9caa00b12"
     cluster="m2319.2b9b91b9caa00b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker clicker script"
     md5_hashes="['469a119ce624f018bf2ad82835c1684e7babcfc6','319db5c306a13cbc8eed6b1aa62843eb717ead75','fccbd7c77e73ee9b08a9f38dbab2c5077b645fce']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b9b91b9caa00b12"

   strings:
      $hex_string = { 41414346772f33764772346e3379564b382f73313630302f736964656261722b68322e6a706729206e6f2d726570656174206c6566743b666f6e743a31387078 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
