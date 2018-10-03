
rule k2318_275253cbc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.275253cbc6220b12"
     cluster="k2318.275253cbc6220b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redirector html"
     md5_hashes="['ae093c1a7bf6a6c6d36be41bc8a4e732a2da7853','07b1adc7716267c6d745d648e919b1a196d09979','2102ebc7571d2b6f999b34183456728c329ec6dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.275253cbc6220b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
