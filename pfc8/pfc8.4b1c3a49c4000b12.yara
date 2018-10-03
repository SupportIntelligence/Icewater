
rule pfc8_4b1c3a49c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.4b1c3a49c4000b12"
     cluster="pfc8.4b1c3a49c4000b12"
     cluster_size="822"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smsreg riskware androidos"
     md5_hashes="['87569e3bc2ffedff492e76523036202bc2a0098c','89bad8ddaaae278f339a7468fe2a2d4a2f3f9342','73d1e81cbf89c213e58ab0eb85604ebac4574db1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.4b1c3a49c4000b12"

   strings:
      $hex_string = { 7cc4f81311a7c29f9c2ce60f475478e91e20e26bb943a4f738e540876a7627efd4ab8c4b0b18f389b794f630284995e38288e7cbbd6e1fee5260f050da58d965 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
