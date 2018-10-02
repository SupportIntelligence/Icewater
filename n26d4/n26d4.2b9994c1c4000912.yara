
rule n26d4_2b9994c1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.2b9994c1c4000912"
     cluster="n26d4.2b9994c1c4000912"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kelios malicious neoreklami"
     md5_hashes="['7625868577b5a17dd4cfdee53c7204eded9497d6','1b712b8faa52435ef89be934f2573e4e652a9c66','974da5d25efea8226abf4478201d763641df44b8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.2b9994c1c4000912"

   strings:
      $hex_string = { 3bf87720394614741b6a0150e82458ffff84c0740f837e1410897e1072028b36c6043e005f5e5dc20400558bec83ec3056576a038d4de8e8eefafeffc745f44e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
