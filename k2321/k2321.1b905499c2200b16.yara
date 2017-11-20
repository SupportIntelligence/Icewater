
rule k2321_1b905499c2200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1b905499c2200b16"
     cluster="k2321.1b905499c2200b16"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['081db2f6226a075b4bad895168c0c764','0f22c7630d686a09319a6f1b9d5aa66d','ab357a965d440d72ff81269c58ed6bd5']"

   strings:
      $hex_string = { ef72e3841dbffd0eb32edfc9e1eed0381874d0b7a3494d73e248711e7edd294305dc69a220836c47f0e80144596b08eb3cb28236c5f54bae23c94a9242dac79e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
