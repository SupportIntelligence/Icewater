
rule k2318_33129eb9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.33129eb9ca800b12"
     cluster="k2318.33129eb9ca800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['1c568cadd4a3b1a5f1465e8b397d7beefb658fa0','ab865c47a1d86e099b947c2d4bcc66b32dd23a1b','fb102bf10fb92837a93b552ab0a050cf55826ff3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.33129eb9ca800b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
