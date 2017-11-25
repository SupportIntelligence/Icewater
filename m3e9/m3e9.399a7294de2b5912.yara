
rule m3e9_399a7294de2b5912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.399a7294de2b5912"
     cluster="m3e9.399a7294de2b5912"
     cluster_size="61"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator trickler gain"
     md5_hashes="['01fb91acfc07b363668596e3bec20b7b','062c320393fa3a34b99383d9517cbebf','43cd76ad1ac8b360b71ee6ea0db1ad0a']"

   strings:
      $hex_string = { 33db833d24ec4200017e0c6a0456e8e61f00005959eb0ba118ea42008a047083e00485c0740d8d049b8d5c46d00fb63747ebcf83fd2d8bc37502f7d85f5e5d5b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
