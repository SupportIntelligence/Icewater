
rule m2319_599b9cc1c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.599b9cc1c4000b32"
     cluster="m2319.599b9cc1c4000b32"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['177e3f5cf47f1016c2b7a737244c78ce','33a728f6f60adf0f6e7fb87c69557416','965dbd6eac3bd254a077bab6410e8198']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
