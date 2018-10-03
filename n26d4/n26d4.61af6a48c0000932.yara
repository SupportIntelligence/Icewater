
rule n26d4_61af6a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.61af6a48c0000932"
     cluster="n26d4.61af6a48c0000932"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cloudatlas neoreklami malicious"
     md5_hashes="['fa7d6d597df1790328b355abe72d3bc0376a4edf','279329fec7705c6a4fd71eb716308ac018a0b92e','247330cc934f19eaeff85f2f171cca8aa1c64a92']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.61af6a48c0000932"

   strings:
      $hex_string = { 33c9538b5d0c2bd843d1eb3b450c568b75100f47d985db74238bf80fb70750ffd28b55f48d7f0266890683c6028b45fc408945fc593bc375e28b7df089375e5b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
