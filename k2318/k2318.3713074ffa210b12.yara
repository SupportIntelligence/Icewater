
rule k2318_3713074ffa210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3713074ffa210b12"
     cluster="k2318.3713074ffa210b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="html iframe redirector"
     md5_hashes="['b385a2aa3b87b09a9bbdc2162ca7d4df38e89c51','f9c7b19b179447553b64d1f093c1d6bc9652da75','2586fad6339ce8db683541f3efed6fb4ccc9fd12']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3713074ffa210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
