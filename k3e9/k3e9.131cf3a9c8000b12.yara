
rule k3e9_131cf3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.131cf3a9c8000b12"
     cluster="k3e9.131cf3a9c8000b12"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy injector backdoor"
     md5_hashes="['1c497769864fefea67ba9be810b81ea6','3529e275b7e7522e7e53f09fe41ece42','de8f6dea6cc035e14f1fdedb8c9cd7e7']"

   strings:
      $hex_string = { 21ebbc0395bc051a9ba03365500f1ac00b90ff8817a180e24fdd27260914fc3510d0d61d3c480019b6a80cba414da3917fd3ed690102af49a6e4f3b815ca772c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
