
rule n2319_39344c869d6f4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.39344c869d6f4912"
     cluster="n2319.39344c869d6f4912"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['e5006f824a52c3d1deff81466ce39517276fdad2','5a919b6dbf5254964c079c79579ae24fe6eb1c34','9fe055fcf8d75f922adae46a9f3d54511eae0593']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.39344c869d6f4912"

   strings:
      $hex_string = { 3b66756e6374696f6e20676574546f74616c4d656d6f727928297b72657475726e20544f54414c5f4d454d4f52597d4845415033325b305d3d31363638353039 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
