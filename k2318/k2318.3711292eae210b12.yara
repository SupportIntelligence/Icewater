
rule k2318_3711292eae210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3711292eae210b12"
     cluster="k2318.3711292eae210b12"
     cluster_size="294"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['fcf6168a6af4a6fbe0d450a0a635e5554318ae88','728da038112e9df2ca7b80deabdee678288d656d','9944f6aba4273beea0b6bec1c893473a0ad14185']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3711292eae210b12"

   strings:
      $hex_string = { 7a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
