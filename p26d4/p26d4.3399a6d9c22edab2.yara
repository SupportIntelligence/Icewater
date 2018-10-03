
rule p26d4_3399a6d9c22edab2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p26d4.3399a6d9c22edab2"
     cluster="p26d4.3399a6d9c22edab2"
     cluster_size="74"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="wajam malicious riskware"
     md5_hashes="['3580bcab6bd6aea27a6c857a9911f099e8062558','4e4e27c6755e6963348e9b544e364fccd58e3084','3a67e61951546a56a10097ae27213775b37f9278']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=p26d4.3399a6d9c22edab2"

   strings:
      $hex_string = { 006162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a303132333435363738395f }

   condition:
      
      filesize > 16777216 and filesize < 67108864
      and $hex_string
}
