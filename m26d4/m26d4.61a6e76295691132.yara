
rule m26d4_61a6e76295691132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.61a6e76295691132"
     cluster="m26d4.61a6e76295691132"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch webtoolbar malicious"
     md5_hashes="['7d0c648973012088b65bdb14f74b220e4f373f8a','77cd37bc0fa639a4ac914bc1a58136542af379ab','d8970d8940cf61a75f42af49630e6ac557561750']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.61a6e76295691132"

   strings:
      $hex_string = { 040200000f387e83504f5055504d454e555f434c415353571500536b696e20312e302054797065204c696272617279571c0050736575646f205472616e737061 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
