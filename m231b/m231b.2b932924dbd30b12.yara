
rule m231b_2b932924dbd30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.2b932924dbd30b12"
     cluster="m231b.2b932924dbd30b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['3df1c7defad4d1d85999f74ab4f04f5f','682452ffc6ca63241d0cabca90c58a13','f2b02c7f2dadca9cdde2c4c0cfd9f4fa']"

   strings:
      $hex_string = { 7263682f6c6162656c2f424c4f472532304445535441515545273e424c4f472044455354415155453c2f613e0a3c7370616e206469723d276c7472273e283629 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
