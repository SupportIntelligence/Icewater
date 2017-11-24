
rule k2321_2b18c545dfa30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b18c545dfa30912"
     cluster="k2321.2b18c545dfa30912"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jtlp kryptik hupigon"
     md5_hashes="['0dc044b2ceea081750cb493249ee5355','1aa3c0ce1927d9f61ecc2f53f7b31409','fd4a58be98d6fa3d0a1b580d6945ccc7']"

   strings:
      $hex_string = { 90a0c0c7727bceab2dee271b52f9a3576bad30e8b1e50c88773d2716e041fdf9e69b8c08cf35369e052bb2d4c6c2922ed5246967dd2cb3123cf28ea45cffca7e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
