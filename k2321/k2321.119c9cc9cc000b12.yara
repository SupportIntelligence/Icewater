
rule k2321_119c9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.119c9cc9cc000b12"
     cluster="k2321.119c9cc9cc000b12"
     cluster_size="184"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vilsel aems heuristic"
     md5_hashes="['00b0462b5926e668735c2f71bf461d1d','00bf68a4edcfe93dafc63d134d7d13b6','174b21c1b0864916273c917c04f2a33b']"

   strings:
      $hex_string = { 53ab41304b0ebb5e2b762868c44d7a1bbd3c22f38c5abeaff19eb98b49938852f40abeb04c45ea8659c1049b446a1aa6bee0944851cc79b6dc4a9da35485953a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
