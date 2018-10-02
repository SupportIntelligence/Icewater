
rule m26d4_29eac72c94576b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.29eac72c94576b32"
     cluster="m26d4.29eac72c94576b32"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious heuristic stantinko"
     md5_hashes="['350c7e2d08caf3228fac02e7165f7636ea078656','0cf352df9aa784ba94699bc39fbe71bec6ae5742','7370f14a9fab5d31918fb9faf09605a15da8bc10']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.29eac72c94576b32"

   strings:
      $hex_string = { 2d86dc827e4775a6eb24c437fd7e33e822930100eb1874b38bcee857b80100eb0da85bc6d6c88bf885ff75e385f6e903ffffff5f5e8be55dc390d5a100100ba2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
