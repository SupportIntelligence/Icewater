
rule k2318_371156d3dee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.371156d3dee30b12"
     cluster="k2318.371156d3dee30b12"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['78cd7473e1781ce7ed30f673f2e908b605b67459','167293737aa05a3a0aaa441359c5d711bc4b1f64','b2a8fcb3e002f27821c7ee19fb20e2c8cd85c7f1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.371156d3dee30b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
