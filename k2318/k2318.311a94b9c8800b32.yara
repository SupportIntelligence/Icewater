
rule k2318_311a94b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.311a94b9c8800b32"
     cluster="k2318.311a94b9c8800b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['fd93a26ec94dbaa2d3868eea8697ba6d593069f4','fb0ae16e8a09d29d74f475603acd055afa1242a2','fe009d9291f9b2285399c1165321d9bfe74b1c98']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.311a94b9c8800b32"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
