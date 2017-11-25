
rule o3f1_139b9bc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.139b9bc9c4000b12"
     cluster="o3f1.139b9bc9c4000b12"
     cluster_size="43"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos hiddad hiddenap"
     md5_hashes="['018e5b04904465ddbbccc43633f5f3a0','18588245e8b2c4e7c9311bb2141a4ca9','76ffd6d7c5388246bb9f9ee6119e0268']"

   strings:
      $hex_string = { 4d74524e53001f77bae5fa78201ca5fcfda71e55f2f358806efe71a3f88f33070c3692f9e42d2f752eb790e33409fbe735b969300bf1566f9a989c8182837f0e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
