
rule k2318_5718a6b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5718a6b9c8800b12"
     cluster="k2318.5718a6b9c8800b12"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['561ee0cf6bdc5833f8d5952626ce08b1a6a7b3f4','9ed3a8fc4b7295867a363d08c72d0827c03db5b1','7cee733853496a3988987570bca81248d5ae8225']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5718a6b9c8800b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
