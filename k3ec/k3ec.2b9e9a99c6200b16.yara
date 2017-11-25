
rule k3ec_2b9e9a99c6200b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.2b9e9a99c6200b16"
     cluster="k3ec.2b9e9a99c6200b16"
     cluster_size="7"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms hacktool kmsactivator"
     md5_hashes="['47ee98182ac6bc5e1e9285ed80b092de','6123824b35cc381c5036638706f2e32f','f6f1ae00810f064481ced3a41bda2603']"

   strings:
      $hex_string = { 8bdd22f6f1bb8f9c54c92fcd2b083f674ef29ba7b8df474af87b27a1bc430c5bff602e5cd4190e469218f74bec3715ccbd6fc373b52cd3626a537cc6a5753457 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
