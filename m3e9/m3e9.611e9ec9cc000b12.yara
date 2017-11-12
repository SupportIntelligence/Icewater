
rule m3e9_611e9ec9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e9ec9cc000b12"
     cluster="m3e9.611e9ec9cc000b12"
     cluster_size="1302"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack allaplet"
     md5_hashes="['00372d9d08604e3b11c528df1ac0c6ef','0060c4e157cdc4fd9a9bd7417afb9986','094b8c572f465a2d816c490c0f75b7c3']"

   strings:
      $hex_string = { 7b7def7ca37f377ecb790cd66de5e9f4650be11a5d29d938554fd18d6373d476b8903c91c0924493c8944c95d0965497d8985c99e09a649be89c6c9df09e749f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
