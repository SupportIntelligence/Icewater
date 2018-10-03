
rule k2318_291a96c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.291a96c9c8000932"
     cluster="k2318.291a96c9c8000932"
     cluster_size="63"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['04d5a842964cceb1a7bcaa6f296fd96e2d3670da','96129157712125a94fc8f61c0d6cccc683ff3d54','e479e809b5107c07755920f3025d97fec1d2a8d5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.291a96c9c8000932"

   strings:
      $hex_string = { 2e7375626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c454354 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
