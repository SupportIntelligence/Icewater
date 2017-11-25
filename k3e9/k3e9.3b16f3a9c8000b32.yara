
rule k3e9_3b16f3a9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3b16f3a9c8000b32"
     cluster="k3e9.3b16f3a9c8000b32"
     cluster_size="68"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['01225fa67e2a826f0fc8d6cd40226153','02a2a54ff1f15e6733d1fe11968ad58e','a3ec9aa5708692b5e7d478fc63aa948d']"

   strings:
      $hex_string = { 21ebbc0395bc051a9ba03365500f1ac00b90ff8817a180e24fdd27260914fc3510d0d61d3c480019b6a80cba414da3917fd3ed690102af49a6e4f3b815ca772c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
