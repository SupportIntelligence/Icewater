
rule k3f7_27524a66cbeb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.27524a66cbeb0b12"
     cluster="k3f7.27524a66cbeb0b12"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html redirector"
     md5_hashes="['0f936125bd1b1c7d0bf4a50667e3246d','4d0d6d468485c0db404c89333c48e4f8','e37ec04f809a1481fd92731ab601208c']"

   strings:
      $hex_string = { 3e3c696d67207372633d22696d616765732f706978656c5f7472616e732e6769662220626f726465723d22302220616c743d22222077696474683d2231303025 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
