
rule k2319_3a54aab489596b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a54aab489596b12"
     cluster="k2319.3a54aab489596b12"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['16204b63d96b6d967a4766017cbd106bfd2120e6','151dda6cbb7845c21b988ea16bbbd2b0d653e5a2','c6448af2c329ee3c718fdda50a00b264aa6f8cdf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a54aab489596b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
