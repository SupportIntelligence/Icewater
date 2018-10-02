
rule k2319_391456bdc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391456bdc6220b12"
     cluster="k2319.391456bdc6220b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9c3201385418a2c15a54be7e5bdc1ecc4a7a9f2c','f1b173c42b423ea731ea0b7d02f2523feb1af802','cff290a0ab784621409553970c3be6aa458f31a6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391456bdc6220b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20475b6f5d3b7d76617220433d2828307846442c392e37324532293e2830783137392c39352e36304531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
