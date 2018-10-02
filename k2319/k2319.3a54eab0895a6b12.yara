
rule k2319_3a54eab0895a6b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a54eab0895a6b12"
     cluster="k2319.3a54eab0895a6b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['76f2fcbc545072fa3ef4d9942188a93eb90bea1a','d9db877b0fe710a7a8a2ac138b3247c74367895b','4da56e803b59167f607f6ed0d9da24f6f9ca5578']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a54eab0895a6b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
