
rule k2321_211c1199c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.211c1199c2200912"
     cluster="k2321.211c1199c2200912"
     cluster_size="20"
     filetype = "PE32 executable (console) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms hacktool kmsactivator"
     md5_hashes="['0af1ce466d8990ac22f96fa815435581','10091d584394d4661f7ee3a8e8f97a63','d2ae6e8d97f9ec75c31f1a85a7cd2b1d']"

   strings:
      $hex_string = { 5e89cedd0c4c554ff44dc4523bd5960dbf059fb709532b0f423834e327fc29bbb4717886b2d2a20dee338b20f15b6f7f54a0f68d3e1a9b6346b1bdd34b6eb982 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
