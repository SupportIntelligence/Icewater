
rule k2318_27534366dbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.27534366dbeb0b12"
     cluster="k2318.27534366dbeb0b12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['413b138ac2daaa9dd1a3ed2f86e123336bbaf4e2','a98948d84ef4c43ef5837e60e7b5bb07e0df8e97','50cfc648e61f1e96fb53e7e6889181d3cb5d551a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.27534366dbeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
