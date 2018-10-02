
rule k2318_37534a44cbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37534a44cbeb0b12"
     cluster="k2318.37534a44cbeb0b12"
     cluster_size="60"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['3fde19f15a9dff9c31d616480499ea20ad6c8991','6f729985f7bedaab8bb7a79bb27f9d212be24a5b','e95c9bb0b788c95dbb5b9fa141b1d65f4cf05442']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37534a44cbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
