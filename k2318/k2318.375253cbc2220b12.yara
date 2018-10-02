
rule k2318_375253cbc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.375253cbc2220b12"
     cluster="k2318.375253cbc2220b12"
     cluster_size="156"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['6f7521ecee2d05947c5139efec72847105c6b637','97d5f0b9425c724128cbf1bcbe4786a46acc75fd','4f618c1c118c3e0846a49b7248d157aad285e1ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.375253cbc2220b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
