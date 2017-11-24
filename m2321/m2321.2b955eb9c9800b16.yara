
rule m2321_2b955eb9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b955eb9c9800b16"
     cluster="m2321.2b955eb9c9800b16"
     cluster_size="15"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma tinba"
     md5_hashes="['066071bb9236558a191f0913f8537270','0ac8b383a99067d72a2a775a5f894cef','fb5c230f3a0e582d0fbd5304ea69b8fa']"

   strings:
      $hex_string = { 3fc47611076d043a55ee810dfea409e31f7e70d5ce1defb6349cb975ed72dfcdebbfc306977f84496efcf2d3e50be73b5a9bf7efdbfbd4134f1417e40f1a9000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
