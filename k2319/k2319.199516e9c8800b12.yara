
rule k2319_199516e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.199516e9c8800b12"
     cluster="k2319.199516e9c8800b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['860dd4d16c5a3e3f13edf030d899bf8be48e3c4d','e595a743baa14ddf1488e028f1308890cc66b90c','8b188071fc229f682d1202fcbe11b66e00b009d3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.199516e9c8800b12"

   strings:
      $hex_string = { 646566696e6564297b72657475726e204c5b585d3b7d76617220483d2836352e3e3d2830783133372c37322e293f22474554223a3133372e3c2830783143352c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
