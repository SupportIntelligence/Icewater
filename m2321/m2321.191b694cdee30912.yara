
rule m2321_191b694cdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.191b694cdee30912"
     cluster="m2321.191b694cdee30912"
     cluster_size="200"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre waski generickd"
     md5_hashes="['00878bbc172173824cc1221aed0096d6','00b8eaf9ed56a3eb11ab7ed3fb2e7af8','1cc4710fffbb94a3b161083c00dd36ce']"

   strings:
      $hex_string = { f706299232a1bdb703cd7d693c081a8fd55471ab603a65d1fbc8e847d039f605b0945d87fe96e81b2534a38936e2b3830a6bc304cb16b29014a9b940558a8030 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
