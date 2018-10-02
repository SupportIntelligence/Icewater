
rule m231b_06e76b3996830912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.06e76b3996830912"
     cluster="m231b.06e76b3996830912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos ppsw score"
     md5_hashes="['527610f6c244669f70bedb4370d55965514352bc','5b431787b04795d432b26ad30a4e1c43479a5a0c','2417fd834b681829b502362a5aa397d25276c50c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.06e76b3996830912"

   strings:
      $hex_string = { 20daafd8b0d8a7d8b1db8c202e2e2e3c2f63656e7465723e273b0a0976617220786d6c687474703b0a096966202877696e646f772e584d4c4874747052657175 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
