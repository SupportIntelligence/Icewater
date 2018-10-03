
rule k2318_3312d48bd6c30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3312d48bd6c30b12"
     cluster="k2318.3312d48bd6c30b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['fbf8fb0a6c4965fb480e6c9754fc098d5fc94a53','e8ee45c3d5d93fddd385001805b9193ce7e390a0','0735c1ee2ba584cbfe0d70eecfcaedda64cde37e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3312d48bd6c30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
