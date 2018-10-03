
rule k2318_33524552cda30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33524552cda30b12"
     cluster="k2318.33524552cda30b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['ab7d8fb96a4e9b6e5b3be8b5d35759a37571ec05','5b7bca817db8d6051d02dfec5d259ec42f3e0549','73f2ffccdbcd74b06d968a3159d61a2f3d2685d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33524552cda30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
