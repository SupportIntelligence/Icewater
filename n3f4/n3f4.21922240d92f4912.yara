
rule n3f4_21922240d92f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f4.21922240d92f4912"
     cluster="n3f4.21922240d92f4912"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious heuristic kryptik"
     md5_hashes="['091a77756e71d0fde556b409640fa164','0b7c4f25ae517275f33ca211ffb12bb4','f18f42a9baa60bee86a71c33bc27d74d']"

   strings:
      $hex_string = { 626d3966614531426b724743486a5176775a4934694c7653337149566750736750756f57486474456d4e7a754b526f4346783550584e7961702f635544654d2b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
