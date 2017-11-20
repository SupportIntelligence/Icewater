
rule k2321_2a2652545ab348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a2652545ab348ba"
     cluster="k2321.2a2652545ab348ba"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy tinba flmp"
     md5_hashes="['70ece1f482ad383c374d9793bf27a03b','873c4920c801a99dd1dc788bdb555b3d','fef9768d1ddaf3acafb725602625982b']"

   strings:
      $hex_string = { 0d25a8a4c92c412bf84ad6f579e5ab5ee39c837b779c96c005506a8dbf582b3cacf11769a284fa5d643457ccb4ec6e9a369899017846a1954c9f70cdcfafe487 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
