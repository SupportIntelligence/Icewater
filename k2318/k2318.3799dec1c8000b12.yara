
rule k2318_3799dec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3799dec1c8000b12"
     cluster="k2318.3799dec1c8000b12"
     cluster_size="4588"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['67e41579b45ea3be2b2f85726790065d7e11ea8e','9c688e1bc99ee785b7c8f302c25eb6ffb77c4399','987b7d92c5a419d1f20e1e8a1900bd95dc054336']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3799dec1c8000b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
