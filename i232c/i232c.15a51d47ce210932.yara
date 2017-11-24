
rule i232c_15a51d47ce210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i232c.15a51d47ce210932"
     cluster="i232c.15a51d47ce210932"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html phish invoice"
     md5_hashes="['3412171bbf7c1106cadd624ef1b5dfd9','3f7b16e2a5325643670d54a2edb3051e','b984fde36de81080ef4a54fc476d248f']"

   strings:
      $hex_string = { 5055424c494320222d2f2f5733432f2f4454442048544d4c20342e3031205472616e736974696f6e616c2f2f454e223e0d0a3c68746d6c3e0d0a3c686561643e }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
