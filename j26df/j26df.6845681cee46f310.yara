
rule j26df_6845681cee46f310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26df.6845681cee46f310"
     cluster="j26df.6845681cee46f310"
     cluster_size="212"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adload nsis cloxer"
     md5_hashes="['ed4b346bf815e1b2f6bf8ef52a1d70afa889a691','60007f3be2697c0bc03f4a48bf4d97d98b8e8835','fc4212d983e27d3fac4a6dbb9dc9e35e4d0cab24']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26df.6845681cee46f310"

   strings:
      $hex_string = { 2c2669322c266932292069202e7237006b65726e656c33323a3a4765744c6f63616c54696d652869296928723729006b65726e656c33323a3a47657453797374 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
