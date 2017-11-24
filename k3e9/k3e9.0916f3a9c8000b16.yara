
rule k3e9_0916f3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0916f3a9c8000b16"
     cluster="k3e9.0916f3a9c8000b16"
     cluster_size="180"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bqbqxwpi injector backdoor"
     md5_hashes="['01005fccba730c3da32b124d21a9c0b7','086485ed88fa3973764e5f714c4daaa3','47f2e307e34d9893f3a4039bdfe3c7c1']"

   strings:
      $hex_string = { 21ebbc0395bc051a9ba03365500f1ac00b90ff8817a180e24fdd27260914fc3510d0d61d3c480019b6a80cba414da3917fd3ed690102af49a6e4f3b815ca772c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
