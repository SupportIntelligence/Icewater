
rule m2321_29b4e8b5d9a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.29b4e8b5d9a30912"
     cluster="m2321.29b4e8b5d9a30912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bundler squarenet trackcash"
     md5_hashes="['3d38a34ca6fab4730144492c87b93df9','6849914f52f01f0f09eeb440e355327b','f2202885c1ee1f63ff2939729b5dc19d']"

   strings:
      $hex_string = { 0f5d4c7d034652fb248d5aede80481447c10b260b11a2045d95c887becee82b615836dd5ff50d6140ac8b107dd9125e2ae2e374b38c2b706176841ac3377bfb9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
