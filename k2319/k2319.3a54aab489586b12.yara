
rule k2319_3a54aab489586b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a54aab489586b12"
     cluster="k2319.3a54aab489586b12"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['0eefea4b67e641e7d2b3a348ae1f8c9de54cf1ef','77d5b2ed61cf6d4a06aa40844811ff970a0de2cb','a9e9424607e43c58a255c0292276869c731d784a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a54aab489586b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
