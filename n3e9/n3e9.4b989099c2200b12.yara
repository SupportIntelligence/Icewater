
rule n3e9_4b989099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4b989099c2200b12"
     cluster="n3e9.4b989099c2200b12"
     cluster_size="24793"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt bxdp naprat"
     md5_hashes="['0003b1199cd3a7ea8a2e48148bb3a0a8','000cd77986ee1bbe355755c31373f500','0051eb816eda15f4c5fe59ab9000defb']"

   strings:
      $hex_string = { ab58ddcc4c3e512845cf9191a2c7ab33a3f11f03535d9babf088310b56801960520428de0fa65a8f367d7afc44c9b30abfef025281040b1e0b690d65b80910d2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
