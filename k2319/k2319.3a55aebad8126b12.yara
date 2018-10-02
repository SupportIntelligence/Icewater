
rule k2319_3a55aebad8126b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a55aebad8126b12"
     cluster="k2319.3a55aebad8126b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['1789a72965c6b9c43e753efd829ede09beb3bdd3','4a2f35db5c1f55cae5b100194c15fe220bd73498','dedb3aaf128b092eed6c9102eec29d82901e3934']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a55aebad8126b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
