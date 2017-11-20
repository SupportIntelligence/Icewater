
rule k2318_5910e34ad5a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5910e34ad5a30932"
     cluster="k2318.5910e34ad5a30932"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script iframe exploit"
     md5_hashes="['3507d59985c9039c3b70812d9841e737','8164ed43ea8462c4050d8e8af3f268fb','feec49dc0352da4c3c5c136fef329bfb']"

   strings:
      $hex_string = { 7454696d6528292b272f7363726970742e6a733f69643d31314e4c795f4e576b4836506e4565554d4164323635636937446e677a312e566d5358755a75534267 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
