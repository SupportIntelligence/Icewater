
rule m2319_2b938694deeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b938694deeb0b12"
     cluster="m2319.2b938694deeb0b12"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['2e0a843fd7cd537547afd27b8357666f','6da14f599cf7ffa5e23c346afbdff805','fec0285dc374f985fb038430d4dca163']"

   strings:
      $hex_string = { 7263682f6c6162656c2f424c4f472532304445535441515545273e424c4f472044455354415155453c2f613e0a3c7370616e206469723d276c7472273e283629 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
