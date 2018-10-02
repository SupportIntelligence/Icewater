
rule k2318_3b938cc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.3b938cc1c8000b12"
     cluster="k2318.3b938cc1c8000b12"
     cluster_size="103"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector hackload script"
     md5_hashes="['ddb8c146175a6fbb82c7e6fbce758ac536f33b54','b0622d195eb80c662e3165f07b7480ce9c2eeeb9','0cfed6938413aa3b5cd63db467b88aac79c255d6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.3b938cc1c8000b12"

   strings:
      $hex_string = { 4445582c464f4c4c4f57223e0a3c212d2d206c696e6b2072656c3d2253484f52544355542049434f4e2220687265663d22687474703a2f2f7777772e616e746f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
