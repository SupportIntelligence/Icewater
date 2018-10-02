
rule n26bb_31923910dda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.31923910dda30912"
     cluster="n26bb.31923910dda30912"
     cluster_size="92"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy nymaim malicious"
     md5_hashes="['d2295989fedb3bc786f269ed844da733d7f6a6ad','f5e0cad0336e0125df4d4248e66d9e54ba2c8434','172c4817a0d93530121348c91c0cec30ed72179e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.31923910dda30912"

   strings:
      $hex_string = { fe7b2160574961049856119140ee90356d6a2ba2c6f3f9734b7dc2c83c3a0678750847eddd0b93e4b286d27123b7426810e9a7fdc1dbe7bb0af4972eaa4819ab }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
