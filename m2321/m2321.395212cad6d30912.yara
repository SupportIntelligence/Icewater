
rule m2321_395212cad6d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.395212cad6d30912"
     cluster="m2321.395212cad6d30912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['1e9bfbd98826bd22421958872cf6b586','7ebf4cb6f2e9a0b5bb4be878447ac0a6','f26aed75bf0d3892658fc8972734fe91']"

   strings:
      $hex_string = { fd2f1762b3ce0a29debaf7ec53fc1603dda4144d313ef8263dd14cc2a2cbfbdfafbfc7c6ff6421d8973953b1106c7aaaea42b0e2842b45d67dc9c5a183eb7941 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
