
rule m3e9_431e9ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.431e9ec9cc000b12"
     cluster="m3e9.431e9ec9cc000b12"
     cluster_size="107"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack virut"
     md5_hashes="['001cfccfc89cb8610c4fd7fa4954ffbf','01c94792ba7ed1440ad939324ffbf3ac','75bf7452bc1c7cab0d6df3f30d87bfe2']"

   strings:
      $hex_string = { 7b7def7ca37f377ecb790cd66de5e9f4650be11a5d29d938554fd18d6373d476b8903c91c0924493c8944c95d0965497d8985c99e09a649be89c6c9df09e749f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
