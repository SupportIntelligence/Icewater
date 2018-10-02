
rule m2319_2316650cdee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2316650cdee30932"
     cluster="m2319.2316650cdee30932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script html"
     md5_hashes="['78de71a80f3ca2424ae7042fa1e2fd6753a80d88','ae3c13d1a0eeb35fee09886b387e88bd7fd0791d','7c1b5aed5a38b987bd7473cbeab898c55de830d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2316650cdee30932"

   strings:
      $hex_string = { 456c656d656e744e5328792e7376672c22636c697050617468222929297d3b666f7228766172204120696e2062294c28622c4129262628543d412e746f4c6f77 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
