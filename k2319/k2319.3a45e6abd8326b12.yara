
rule k2319_3a45e6abd8326b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a45e6abd8326b12"
     cluster="k2319.3a45e6abd8326b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['ffb154de0f8bdf6b6816a3d5a868338ce54a75e4','29b48d01abee5af9c6d4cce217ad80dca920c6f8','e1d973b196eb94894c5d083e8b5526f9c96f0127']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a45e6abd8326b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
