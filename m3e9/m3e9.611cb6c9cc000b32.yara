
rule m3e9_611cb6c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611cb6c9cc000b32"
     cluster="m3e9.611cb6c9cc000b32"
     cluster_size="262"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['008f12d349cdb6360311231366ab8ab0','01f4f102e5fa9e1eb11b9644e9ce81f0','1c51fc1f5dec1211bd324118bd88e1e9']"

   strings:
      $hex_string = { 494f36c822410fbafb33e8acd425c19ead179a90860973825ffb4b7438ed246611dffd58ead1d64ac3c3af3c9cb5882e75a761204e993a12278b1304007decf6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
