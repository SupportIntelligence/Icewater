
rule k2319_1a5496a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a5496a9c8800b12"
     cluster="k2319.1a5496a9c8800b12"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem expkit"
     md5_hashes="['dc9b1fee3e7a53303a2390434fc1731ea5524d17','f3d99f295c85ae9744d32364b59c5e5126b9ce6e','a2fa2b8624b56ad7d5bc772fb6b3994720935e1c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a5496a9c8800b12"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20505b495d3b7d76617220533d282839382e3545312c30784144293e3d2837332e3245312c3134322e293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
