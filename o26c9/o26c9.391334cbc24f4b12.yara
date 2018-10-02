
rule o26c9_391334cbc24f4b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c9.391334cbc24f4b12"
     cluster="o26c9.391334cbc24f4b12"
     cluster_size="502"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="bsymem tsklnk dnscleaner"
     md5_hashes="['847efad31d0af4f70f9d24217cfd1e11ebd51d51','c141eeca9b380a2acf08aced50c25862b1ed0a17','16b60907249bee9655f9948c3f697c4b75628a38']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c9.391334cbc24f4b12"

   strings:
      $hex_string = { c5488d4de0418bd5ff15defc1800443965707405458bcdeb358b4b2483f9ff750c41f7de451bc94183e103eb21b2c03aca76180fb7c166c1e8083ac2760dc1e9 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
