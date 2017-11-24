
rule m2319_2b930614ddeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b930614ddeb0b12"
     cluster="m2319.2b930614ddeb0b12"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['0f768907a16fe2b36a3b53007d8efd8e','192e61a3555b254852e7462b59cffa87','e0fcf6f9a24c31ed738885bc71ad5d32']"

   strings:
      $hex_string = { 7263682f6c6162656c2f424c4f472532304445535441515545273e424c4f472044455354415155453c2f613e0a3c7370616e206469723d276c7472273e283629 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
