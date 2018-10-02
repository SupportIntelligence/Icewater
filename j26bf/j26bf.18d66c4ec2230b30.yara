
rule j26bf_18d66c4ec2230b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.18d66c4ec2230b30"
     cluster="j26bf.18d66c4ec2230b30"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious heuristic"
     md5_hashes="['d42c1b3574c04ce0c4dd59dd3254de7796cdc430','bb0326526c287e28f18d2943a3eb0267bfdb0821','33053ac9e32e699be82e0189806a625428746f0d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.18d66c4ec2230b30"

   strings:
      $hex_string = { 7269627574650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56697369626c6541747472696275746500477569644174 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
