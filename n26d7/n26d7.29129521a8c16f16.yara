
rule n26d7_29129521a8c16f16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.29129521a8c16f16"
     cluster="n26d7.29129521a8c16f16"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious kryptik"
     md5_hashes="['f70acf171ee47a6dfd8565aebf914b32479c42d3','b4ab01e2e008e328f31fbc09712c5e89e787999f','f2912bf4d17aa2cce1f6f8066eacb3e29b25762c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.29129521a8c16f16"

   strings:
      $hex_string = { d70bae9a8739be79cb9b31e16eb782efce85aa774d8e78f6252c36600a2fdc0fc40c2086d13861f902841c6fa74847f8f3740612a3ab6b094bfd9200fb671b90 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
