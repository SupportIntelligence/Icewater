
rule m3e9_3a58b39bc2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a58b39bc2220b14"
     cluster="m3e9.3a58b39bc2220b14"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['b107b7b49ab09e2f7331d6b5fd4c1be5','bc3025a17b37c589814d3e2ac9840e24','eaffd8f200d550187ff1fe5d82957c39']"

   strings:
      $hex_string = { 9ab35bb1d9a8cd329fb876ba697d9afbc98740ee070ba08816a93e80e68318bcb47309da6f4b0298799b922225d85f676fca56a5d74c82e1869c2034700081b5 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
