
rule k2319_4b9bad4bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.4b9bad4bc6220b12"
     cluster="k2319.4b9bad4bc6220b12"
     cluster_size="386"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['7d963eb891cfb91a573b36b6c3a4a42ce862dad3','0433db1a36f44c00d3137238045db2243ed7868d','4a59806aff2d0a0704ab66b8fe39552b3c532ddf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.4b9bad4bc6220b12"

   strings:
      $hex_string = { 3c21646f63747970652068746d6c207075626c696320222d2f2f5733432f2f4454442048544d4c20342e3031205472616e736974696f6e616c2f2f454e223e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
