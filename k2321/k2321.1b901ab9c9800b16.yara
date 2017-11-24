
rule k2321_1b901ab9c9800b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1b901ab9c9800b16"
     cluster="k2321.1b901ab9c9800b16"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="small generickd upatre"
     md5_hashes="['05dd4e25e33c18105e4d4e519894b590','120c24fbd1b0da4af4120291fd767f29','ceb75ef6e3ca4a8b5f598ab46a66c20c']"

   strings:
      $hex_string = { ef72e3841dbffd0eb32edfc9e1eed0381874d0b7a3494d73e248711e7edd294305dc69a220836c47f0e80144596b08eb3cb28236c5f54bae23c94a9242dac79e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
