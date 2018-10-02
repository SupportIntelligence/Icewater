
rule k2318_371329aeae210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.371329aeae210b12"
     cluster="k2318.371329aeae210b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html jscript"
     md5_hashes="['c814776f5f9dac1a0300a1ac824dcb5f36ae641d','adce1397859f5f3db99d6ca26a1e4adf66c2b48d','f35a5b975353f0e65267d4acde357cae88c5c3a0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.371329aeae210b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
