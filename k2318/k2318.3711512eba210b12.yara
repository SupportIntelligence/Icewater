
rule k2318_3711512eba210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3711512eba210b12"
     cluster="k2318.3711512eba210b12"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['70d56bf6b98c11a06c1d447e7fea63b937ee6c8e','cb856b9c0e3cfc87e225f03e89d13f12b56d8f6a','ff4bd737a97080ebd39ec01db50cfa4f5c3b6d2e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3711512eba210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
