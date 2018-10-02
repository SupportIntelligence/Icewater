
rule j26bf_18d66cccc6230b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.18d66cccc6230b30"
     cluster="j26bf.18d66cccc6230b30"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious heuristic"
     md5_hashes="['cc32dc93fd68f3db330533ee5bee7854c883e78a','9d9dd80fc7e2988dc473f892e6c733e65a38f308','10012f3281b06e943e7169c642da68765631784f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.18d66cccc6230b30"

   strings:
      $hex_string = { 7269627574650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c6541747472696275746500477569644174 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
