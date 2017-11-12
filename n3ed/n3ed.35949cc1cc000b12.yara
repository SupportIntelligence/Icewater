
rule n3ed_35949cc1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.35949cc1cc000b12"
     cluster="n3ed.35949cc1cc000b12"
     cluster_size="393"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['042e49e6eaa5ee3e5e8f0b542bd9bca3','07548832d83d4193b4a711d4d337e395','2691dc38e31d22c9f9bf01b8f44b6cfd']"

   strings:
      $hex_string = { 00292e43c9a2d87c013d3654a1ecf0061362a705f3c0c7738c98932bd9bc4c82ca1e9b573cfdd4e01667426f188a17e512be4ec4d6da9ede49a0fbf58ebb2fee }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
