
rule k2318_3713298ebe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713298ebe210b12"
     cluster="k2318.3713298ebe210b12"
     cluster_size="91"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['3fb9dcac2c7ee64b89f6e62124532468c20d7ae4','e7b0b3912e51e0b0da6bbe070ddf3c477f198c6d','39de74bb212793482bc2c4ed4f6466e22b9c6f98']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713298ebe210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
