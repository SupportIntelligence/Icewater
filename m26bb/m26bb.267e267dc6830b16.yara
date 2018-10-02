
rule m26bb_267e267dc6830b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.267e267dc6830b16"
     cluster="m26bb.267e267dc6830b16"
     cluster_size="117"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious onesyscare adinstall"
     md5_hashes="['a394d9ea85a10d3450ca65719e60d82dbd6caa47','8c9ff2c5d7fb77117e33a47e989b6628eded77f2','265ddca4815d83d927960cd6cdf07d6ecf1a223c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.267e267dc6830b16"

   strings:
      $hex_string = { bf6af1463e0b34379bb9b7dc08cfdf9cdb53ca1fb390a7d4bbb60164d0446742bdc48f3528ac934aabce8376f76eadec0d5641e96d7ca88a40e233d3654ee1a0 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
