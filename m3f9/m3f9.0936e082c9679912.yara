
rule m3f9_0936e082c9679912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.0936e082c9679912"
     cluster="m3f9.0936e082c9679912"
     cluster_size="44"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="firseria bundler fiseria"
     md5_hashes="['0e1d0f39672d184e005ccbb5d575e3c6','19a33467b021fa91d009bda734c7a5ae','b6c2a1b51392590969ea25cf28c12104']"

   strings:
      $hex_string = { 848ca593746add417fd9b3bcf95f5b6c1e0bc9d467bf80fef28263e2cc08791b66b28d65a2e97c70de31980d3eced21de41f163b5976d7c21a5afc2de3c8487d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
