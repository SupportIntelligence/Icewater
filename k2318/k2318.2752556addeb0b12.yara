
rule k2318_2752556addeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2752556addeb0b12"
     cluster="k2318.2752556addeb0b12"
     cluster_size="234"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['bf1844bc9fca0cc7e462b1d438114c751d27d3f8','12e42e0700b36fb214a07658440b7a51ebd897ec','0882d11b691aea8279f1f9b2e4d090b53988162b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2752556addeb0b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
