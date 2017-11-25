
rule k3e9_0b10f3a9c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0b10f3a9c8000b16"
     cluster="k3e9.0b10f3a9c8000b16"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor tofsee injector"
     md5_hashes="['a7bdd8854a96c96c25df1053900ea0f8','c85f248e69d6ab6035cb678085c76fb0','fb3aae8a2994e050894a1bcb42897aa4']"

   strings:
      $hex_string = { 21ebbc0395bc051a9ba03365500f1ac00b90ff8817a180e24fdd27260914fc3510d0d61d3c480019b6a80cba414da3917fd3ed690102af49a6e4f3b815ca772c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
