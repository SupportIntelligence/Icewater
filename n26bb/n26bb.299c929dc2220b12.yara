
rule n26bb_299c929dc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.299c929dc2220b12"
     cluster="n26bb.299c929dc2220b12"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="incredimail malicious perion"
     md5_hashes="['30f8a40be2e7c857483ce191ced7bc7d0d554035','1923795a80c3c23d6337f13794a7b9daf1903963','874bc4c0cbc5743b38fbc131cd35043e3cc41047']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.299c929dc2220b12"

   strings:
      $hex_string = { 6d1d3ded41650a53dd160fa1cd8e2a015282fdd260f63ed7e6a7fb9058f5aa4a42514e30271839bb34741bf98b724498471992052be8753815b368995ec797ea }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
