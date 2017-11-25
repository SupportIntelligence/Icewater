
rule m2377_2b931114d6c30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b931114d6c30b12"
     cluster="m2377.2b931114d6c30b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['03aeb3c62b3ca777267b160acd58f83b','0f8b2dcf5aa37ab5afe57fab43a28f52','db06456980b5df7fe3c5f82f1a68e698']"

   strings:
      $hex_string = { 6b2720687265663d27687474703a2f2f626262692d696464642e626c6f6773706f742e64652f323031352f30372f273e4a756c793c2f613e0a3c7370616e2063 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
