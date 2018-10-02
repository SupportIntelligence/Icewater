
rule j26bf_0856ee45ae210b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.0856ee45ae210b10"
     cluster="j26bf.0856ee45ae210b10"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo filerepmalware malicious"
     md5_hashes="['f25639c565b1e839d92b81d864909a0161fc42d6','00055fb0954e7134648c7cb64fff21c16a839f72','b10aebc55efb28f1f71824959257566b5bf842a4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.0856ee45ae210b10"

   strings:
      $hex_string = { 6c79436f6e66696775726174696f6e41747472696275746500417373656d626c79436f6d70616e7941747472696275746500417373656d626c7950726f647563 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
