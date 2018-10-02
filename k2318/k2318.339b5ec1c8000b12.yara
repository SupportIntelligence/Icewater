
rule k2318_339b5ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339b5ec1c8000b12"
     cluster="k2318.339b5ec1c8000b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['ef595797e1fb0f9b7289ee3fd3e3fce82f1746ca','8cfd0ec2905830c7fd001bf27d68b6723bb75d25','2bb2870b9765df9ce374735d33a40f7dc86c740b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339b5ec1c8000b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
