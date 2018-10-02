
rule m26bb_396eb0c188001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.396eb0c188001112"
     cluster="m26bb.396eb0c188001112"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore click software"
     md5_hashes="['a90feee813af792d82334bf1f92e371b066748f8','1b062b53f987a8af5e03cfb63c8ccdc4e770b8f4','b90394284018300575da9567f53f85d97dac81d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.396eb0c188001112"

   strings:
      $hex_string = { ffb74d00ffba5102ffbe5604ffc05906ffc45d09ffc6620cffca670effcd6a10ffd06f13ffd27216ffd57619ffd87a1affda7d1dffdd8020ffdf8422ffe28825 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
