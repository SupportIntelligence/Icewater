
rule k2318_27335662dceb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27335662dceb0b12"
     cluster="k2318.27335662dceb0b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['a029219db1ac74c58a210cac8a5c839557c96f6b','b91bd0b3bf181f94aaf82b93b9d6d6cbe1c6aa72','1dcc948c8c0a4109ca95c1fd5714644b83264eff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27335662dceb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
