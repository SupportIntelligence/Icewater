
rule k2321_293c9cc1cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.293c9cc1cc000912"
     cluster="k2321.293c9cc1cc000912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="selfdel zbot generickd"
     md5_hashes="['4a4938558b0f73c336e3a431e5272656','8c22fa41a78fcad9598978bc8f2f9b41','b9547313ecda335f09f058510f6fa96e']"

   strings:
      $hex_string = { a5c7ce343e4ab3e057cb6fb6c82c0da286da4111bd3a2e95d74b04973cb97690a7b5bee4d10b8e8c4ff0b246536815994291a8709b455d2be1197150e25ad459 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
