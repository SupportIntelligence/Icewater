
rule m3e9_631c9ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.631c9ec9cc000b12"
     cluster="m3e9.631c9ec9cc000b12"
     cluster_size="345"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack starman"
     md5_hashes="['03b424ff284772b17e512013c11a9f53','051c8a7c6d56d505d4a6502a9c39c745','34340263cf92b69733f3971f7bee63e4']"

   strings:
      $hex_string = { 7b7def7ca37f377ecb790cd66de5e9f4650be11a5d29d938554fd18d6373d476b8903c91c0924493c8944c95d0965497d8985c99e09a649be89c6c9df09e749f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
