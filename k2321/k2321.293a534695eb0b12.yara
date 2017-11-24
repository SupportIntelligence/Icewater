
rule k2321_293a534695eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.293a534695eb0b12"
     cluster="k2321.293a534695eb0b12"
     cluster_size="253"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik doxv"
     md5_hashes="['00a430927d0435cc1884a8936928fbc5','024f627e3887a5303d6edded0233da29','0e84e57a6e7a6f54c20e1dbccb3a3a0c']"

   strings:
      $hex_string = { 3453ae0c3d780557ba812b0422be02c41695a86be8d61f28a4bb84566ec7c012d99c4e572a30a7d1d20dfcc14daf40db0935e0331ce4c8621b60ddf55d4c6732 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
