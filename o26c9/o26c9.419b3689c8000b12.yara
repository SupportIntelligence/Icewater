
rule o26c9_419b3689c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c9.419b3689c8000b12"
     cluster="o26c9.419b3689c8000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="unsafe gamehack malicious"
     md5_hashes="['a4a062d5c8c33b41aa2e240f958f110b2b5eb4ad','0bd536461dfed299ec49b7e09120037e4cd1d691','2706ebf9f92b64c46b6ffd2c396fafc784b9f7d3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c9.419b3689c8000b12"

   strings:
      $hex_string = { bf3a7af76694913233a22643f6279b10a3ca2d3b9d76d7587b6d31db1122d31efbbd740fbb59d983d852726ad2ddf2ee8762696ea8f98d65088be92c1c5def02 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
