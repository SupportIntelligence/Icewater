
rule k2318_2753d6d9c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2753d6d9c6220b12"
     cluster="k2318.2753d6d9c6220b12"
     cluster_size="40"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['f3833737f3891c07a2a6d47559485c0018d70d06','61a18bfd31b8988eadb1798a5b310741edea9ca5','938486b86f6c3b0de874c6f42df43a13c9bfc38a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2753d6d9c6220b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
