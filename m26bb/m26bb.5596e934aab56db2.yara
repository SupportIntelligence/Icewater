
rule m26bb_5596e934aab56db2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.5596e934aab56db2"
     cluster="m26bb.5596e934aab56db2"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious engine heuristic"
     md5_hashes="['3582f855fb04c8b49ea0dfe640383829da6de2ad','8bfd04792946a03bfd1753eba8ea6ff86079c1ab','25e93ca2667db54038f8f5aa1e82ad70ab1f9385']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.5596e934aab56db2"

   strings:
      $hex_string = { 85c0747d395df075788b45fc33c98a68036a02bfa8220001be20ac020133d28a48028bc159f3a7750b66813d1cac02010180740650e83a9dffff0fb7c83b4d0c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
