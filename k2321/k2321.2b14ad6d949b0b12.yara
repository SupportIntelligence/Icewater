
rule k2321_2b14ad6d949b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b14ad6d949b0b12"
     cluster="k2321.2b14ad6d949b0b12"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['044054aa95a147e284a2cabf34be56b8','0ff7aa5b24f968dfdb7a174647f4ed28','fd607545cf46e765c4c65eeafc42c351']"

   strings:
      $hex_string = { fdf4d33da74fff6c6e68387fe1c2e79f7df6f2cb2f6fdcb0a18dcf2b594cc417040fb55c1ea8d58272069d969c99410ff150393e3494e84e5b808b51fae06e31 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
