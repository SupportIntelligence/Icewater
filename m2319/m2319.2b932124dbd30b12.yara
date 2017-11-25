
rule m2319_2b932124dbd30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b932124dbd30b12"
     cluster="m2319.2b932124dbd30b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['1b67b1d32d5d60fa40ef32d6b3dffb51','5b0e9be32bd4ea63fd76f9fe1fc9653f','ebb89135fed280cb010c3346a92fe0bf']"

   strings:
      $hex_string = { 7263682f6c6162656c2f424c4f472532304445535441515545273e424c4f472044455354415155453c2f613e0a3c7370616e206469723d276c7472273e283629 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
