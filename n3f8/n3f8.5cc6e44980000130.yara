
rule n3f8_5cc6e44980000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5cc6e44980000130"
     cluster="n3f8.5cc6e44980000130"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker piom"
     md5_hashes="['0390d5bbdcef33a11b8f926e3ddd24360bfbb8da','33a4b58bb878e8eb3ecf56c3266e2d290f919b51','2f4fd540726932eb55545063925db0ebdcf6cbff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5cc6e44980000130"

   strings:
      $hex_string = { 2f416e64726f696457617463684578656375746f723b00254c636f6d2f73717561726575702f6c65616b63616e6172792f4275696c64436f6e6669673b00314c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
