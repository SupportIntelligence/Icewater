
rule j3f7_392bb6b6dec10932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.392bb6b6dec10932"
     cluster="j3f7.392bb6b6dec10932"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe html script"
     md5_hashes="['8bbe1a6c0bdd10e175241126de8ef6ff','ac62934f04bbf5e1e6affdb02d77e512','de03451722be4a7342664101c591dfbf']"

   strings:
      $hex_string = { 2069643d22765f6d7973716c2220687265663d22687474703a2f2f7777772e6d7973716c2e636f6d2f22207461726765743d225f626c616e6b223e3c2f613e0a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
