
rule m2321_29b4e8a5d9a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.29b4e8a5d9a30912"
     cluster="m2321.29b4e8a5d9a30912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['19f4c82eab06d18b70081f7a43e7b4e8','cc8b52546f509d090a1fd3264d312a03','ffe3001ef88f09a77da6682b7412d49a']"

   strings:
      $hex_string = { 0f5d4c7d034652fb248d5aede80481447c10b260b11a2045d95c887becee82b615836dd5ff50d6140ac8b107dd9125e2ae2e374b38c2b706176841ac3377bfb9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
