
rule n2319_4911064a96c94d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.4911064a96c94d16"
     cluster="n2319.4911064a96c94d16"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cryxos coinminer coinhive"
     md5_hashes="['ab422af23cd1d193968b841dfdd7bb0d4fbde977','4763ee3cebc4719388cf967a3e160c5f2ecde13d','474ac737adcd5b985f0ccd41dcf7034815598074']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.4911064a96c94d16"

   strings:
      $hex_string = { 2f55492d5472616e736974696f6e3e227d2c7265674578703a7b6573636170653a2f5b2d5b5c5d7b7d28292a2b3f2e2c5c5c5e247c235c735d2f672c71756f74 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
