
rule n26bb_5396e848c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5396e848c0000b32"
     cluster="n26bb.5396e848c0000b32"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="explorerhijack malicious patched"
     md5_hashes="['cecc8bc9eef565221f09aa3de7d880ba0594c86f','6d5a90771f2250d9b1db98aef2c691be6212c35c','2c9bb63e0bdd8689a33a91653f3023783087feea']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5396e848c0000b32"

   strings:
      $hex_string = { d58b46408b4e3cebb6e868f8ffff84c074c78b432485c074c08b57088b4b2851c1e204035318508b46205250e8c5fdffff83c410eba38b4de4c6411c01c745fc }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
