
rule n2706_1812210fa3390914
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2706.1812210fa3390914"
     cluster="n2706.1812210fa3390914"
     cluster_size="58"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="browsefox ursu filerepmetagen"
     md5_hashes="['3a12ed1289779e24db171b081093b9d5548d14d5','af129de22c6354cd077035b4c7129f7c7e577119','9bf95bb97ca40d1e45866a60a20f01079d08e3ec']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2706.1812210fa3390914"

   strings:
      $hex_string = { 4c65737365725468616e4f72457175616c546f00457175616c546f004e6f74457175616c546f0063636237363063636432363365393531373730383466323439 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
