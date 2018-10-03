
rule k2318_37128b6dfe210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.37128b6dfe210b12"
     cluster="k2318.37128b6dfe210b12"
     cluster_size="41"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['9c792e08cdf98d175e8859b0771ab4ca5371f944','65466ccb8c2fc86c6a2de4ea6d24e96fb70dcac5','ff4509877eb207f4e6b786667e82135006274fa1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.37128b6dfe210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
