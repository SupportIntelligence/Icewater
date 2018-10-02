
rule m2726_4d2da1950cb567ea
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2726.4d2da1950cb567ea"
     cluster="m2726.4d2da1950cb567ea"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="stantinko malicious epny"
     md5_hashes="['70f4c695d24681ad8a491b013e79f809c1e418d7','4d76bd0edc80d7aacd4f6c4022ee986171310c58','df0add5350ec9ba45f218bcb7d1a4822fbdc56fb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2726.4d2da1950cb567ea"

   strings:
      $hex_string = { 73fe0f57c0660f2f450c6a058d4d08e81ad6ffff68ca620010eb665c25bf14e150eb5ee845fcffff8b760485f6eb52a4a9af0337743c33f68b86300100008b7d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
