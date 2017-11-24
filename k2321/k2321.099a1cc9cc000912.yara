
rule k2321_099a1cc9cc000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.099a1cc9cc000912"
     cluster="k2321.099a1cc9cc000912"
     cluster_size="14"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['05f1c3f928c9ded3bcf1b4e611ad82cb','2ea66ffff0eff17d5a4b67524717a7b4','fd0cdb247f05b1bce3099c07b323b0c3']"

   strings:
      $hex_string = { 80a5cd53485e216f96a06306ccc04743759cbb7c5c526703d93dec893449f65b22a79b38e587e190dadc29a47a585f2f3b84f368cec31e0718e24cfc7822a3ea }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
