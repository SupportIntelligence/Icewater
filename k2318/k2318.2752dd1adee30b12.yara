
rule k2318_2752dd1adee30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.2752dd1adee30b12"
     cluster="k2318.2752dd1adee30b12"
     cluster_size="39"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['60b17a18fc8559e03ad5f3756fa39f3ab0c96cb2','670c1c11ca6761d2b223ba02d1d12321b4dbabfb','60359a868e7f5fe9c5ac055d3e5e0e5f18f0266f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.2752dd1adee30b12"

   strings:
      $hex_string = { 697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c45435445443ec2fbe1e5f0e8f2e53c2f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
