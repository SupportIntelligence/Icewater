
rule o2319_391b3949c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.391b3949c0000932"
     cluster="o2319.391b3949c0000932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos coinminer miner"
     md5_hashes="['4e32a850340d6f546f836c4cbf9e70740e6c3247','f82d3526a692db6123ea4c45ff918258f3f04261','6c53cdab8e1741bf37a98a5839a4b815908cb390']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.391b3949c0000932"

   strings:
      $hex_string = { 6774687c7c6e2e6572726f722822496e76616c696420584d4c3a20222b62292c637d3b7661722048623d2f232e2a242f2c49623d2f285b3f265d295f3d5b5e26 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
