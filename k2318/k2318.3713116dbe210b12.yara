
rule k2318_3713116dbe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713116dbe210b12"
     cluster="k2318.3713116dbe210b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['a57516a23e7993db8a9c495d815a3f06ee04da8c','b6d56eab5886d4a96b20b14ab4c1f93071e534e5','90e7baa6c459657e5edb10b2d8db6b30f82cb0ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713116dbe210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
