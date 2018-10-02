
rule k2318_339bdec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339bdec1c8000b12"
     cluster="k2318.339bdec1c8000b12"
     cluster_size="258"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['42a0c489e38b6379a45b6a881be65d0ad2ad1d45','d5c661ed829901158b922fe3d3863a28065774b2','ef93389f6045344ab79e193f10ca923da9102961']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339bdec1c8000b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
