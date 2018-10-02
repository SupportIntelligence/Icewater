
rule o26bb_4d9d11a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4d9d11a9c8800b12"
     cluster="o26bb.4d9d11a9c8800b12"
     cluster_size="50"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="filerepmalware malicious razy"
     md5_hashes="['d9ef1e1cf3b68def172685751f4c6337a58115cb','34170717b14778a1e3d1a73b53fa3343c78a1ab0','637f8796e6dfd0d31de031d69b4cd77cd1c971a5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4d9d11a9c8800b12"

   strings:
      $hex_string = { ca83ef0175dd8b45f88b5dfc85c077ae720583fbff77a75f660f1f440000b8cdcccccc4ef7e3c1ea038ac2c0e0028d0c1002c92ad980c330881e8bda85db75de }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
