
rule n2321_11991099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.11991099c2200b12"
     cluster="n2321.11991099c2200b12"
     cluster_size="95"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="incredimail heuristic perinet"
     md5_hashes="['0228d96a36081f6ada7eafb0897186c5','02d2e1e8f3fe03ccfd0b439df834fc80','29be5fbccccdf72a546e1ab1ddc5c21f']"

   strings:
      $hex_string = { 439db86de9e5702aa5b636d3338e4c9bad5c860d97cdb4a3e2086052c57739e645ec73656ffe9e126b92bd06ab090be4eb208190bf80a6df485b6e95bedc3cb5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
