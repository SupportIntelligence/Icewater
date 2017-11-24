
rule m2321_01915b67c91b9932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.01915b67c91b9932"
     cluster="m2321.01915b67c91b9932"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar scudy zusy"
     md5_hashes="['1b5bc9ab7db8e6714aca4d6bef7f09bf','2923ee66406c407ba1c7064c8dae7457','ecb56942e9d6128ea2545e26d70ef822']"

   strings:
      $hex_string = { c751fc633cd02b5c2f809c1000afad760136a749c618e065bb8cc01e42f52e2092cff3db5ff9f2d53f503e0afd892224403964f7910713b47f1922795ba37260 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
