
rule k2318_333349adc6210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.333349adc6210b12"
     cluster="k2318.333349adc6210b12"
     cluster_size="74"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['a644d0d8d663e591c0f93917d698a5eb81d2f3d0','2545edcc3e4139a83847611283b73c4e40c5b2d2','bb55093a6b1b1861a6868d0558941e48a075a78d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.333349adc6210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
