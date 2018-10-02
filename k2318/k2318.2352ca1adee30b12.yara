
rule k2318_2352ca1adee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2352ca1adee30b12"
     cluster="k2318.2352ca1adee30b12"
     cluster_size="70"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['53420a8099805570981aeb6d2331a79a5d87a985','85c43fbc36948e41a540a46fbd939d017d08c4b5','feb050b2c9f34a24521dd0c58387ed4e3340e93b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2352ca1adee30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
