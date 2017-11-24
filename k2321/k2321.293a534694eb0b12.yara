
rule k2321_293a534694eb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.293a534694eb0b12"
     cluster="k2321.293a534694eb0b12"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik doxv"
     md5_hashes="['5a8f602b82fbc820012745270d073e28','5d6f4890d1463f99c7b82c11b2f56473','e58d02a81ebf869657275b671b712c23']"

   strings:
      $hex_string = { 3453ae0c3d780557ba812b0422be02c41695a86be8d61f28a4bb84566ec7c012d99c4e572a30a7d1d20dfcc14daf40db0935e0331ce4c8621b60ddf55d4c6732 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
