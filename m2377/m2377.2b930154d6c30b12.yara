
rule m2377_2b930154d6c30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b930154d6c30b12"
     cluster="m2377.2b930154d6c30b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['afb49003a5c84c2b9768049800f7ccc1','bb260472c7b73895d2dfc23dce68cc83','da519422fe36c2dadcf502d1bc787c2f']"

   strings:
      $hex_string = { 6b2720687265663d27687474703a2f2f626262692d696464642e626c6f6773706f742e64652f323031342f30372f273e4a756c793c2f613e0a3c7370616e2063 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
