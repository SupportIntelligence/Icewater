
rule k3ec_3b5578e192c20b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.3b5578e192c20b16"
     cluster="k3ec.3b5578e192c20b16"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious engine heuristic"
     md5_hashes="['0fccc5a16d5be19e3c06bf575ea656f4','769323dc5650a3f12bfda18fa3311102','f2985b1ab1f005177f68480de64ef401']"

   strings:
      $hex_string = { 6548616e646c65570031005f5f766372745f4c6f61644c69627261727945785700564352554e54494d45313430442e646c6c0014005f4372744462675265706f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
