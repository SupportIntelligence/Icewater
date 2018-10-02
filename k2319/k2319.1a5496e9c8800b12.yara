
rule k2319_1a5496e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a5496e9c8800b12"
     cluster="k2319.1a5496e9c8800b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem expkit"
     md5_hashes="['fe360b7c885a62c92b9d73853de77b4d7e61aaef','7da1e195a2abcc0afe84206fdc1ff54de59eda8c','e80e6d7b357f721509542eb2db9b7d1041aeaf97']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a5496e9c8800b12"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20505b495d3b7d76617220533d282839382e3545312c30784144293e3d2837332e3245312c3134322e293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
