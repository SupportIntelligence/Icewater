
rule m2321_491f121cc2210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.491f121cc2210b12"
     cluster="m2321.491f121cc2210b12"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['1d5514c680b5247eb3b396497a2dc08b','22abc87062952563c742ec6c10b482cc','7210356b2164c31536ed3946032f61e6']"

   strings:
      $hex_string = { 0f93b35533e76cfed9bfd0f73ff646e0432ec3774eabe153e99b1258b9cf8f63eef4190b3210d728a80d7684145ff7f51a16dd864715a7029a6da9c9575bce67 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
