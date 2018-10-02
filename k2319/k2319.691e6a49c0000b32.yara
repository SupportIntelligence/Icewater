
rule k2319_691e6a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.691e6a49c0000b32"
     cluster="k2319.691e6a49c0000b32"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="diplugem script asmalwsc"
     md5_hashes="['9deee4f251fbf15b00cbefcc4c8dd02a744347b3','df0bf9f3166d58ee134cf6bca81aadea6efff7c3','d5484d4e49d2cdf906f44cd75155e7a09717d72a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.691e6a49c0000b32"

   strings:
      $hex_string = { 2e7336452b6c3877392e4c3745292c6465636f64653a66756e6374696f6e28572c51297b76617220653d226f6465222c683d225f64222c6a3d282832362e3230 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
