
rule k3e9_6dd119cdde210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6dd119cdde210b12"
     cluster="k3e9.6dd119cdde210b12"
     cluster_size="149"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious attribute engine"
     md5_hashes="['06b68449f721a4703607c4ee4848a65b','074bd764faaab3e0eb979ac8cbb5f682','241f1819aee4bf6428dc56b6e9bff33d']"

   strings:
      $hex_string = { d080e201f6da1bd281e22083b8edd1e833c24e75ea89048dc87d42004181f9000100007cd58b5424108b44240885d2f7d076238b4c240c570fb6398bf081e6ff }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
