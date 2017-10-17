import "hash"

rule n3e9_29b856c4caf31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.29b856c4caf31932"
     cluster="n3e9.29b856c4caf31932"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="agobot backdoor sdbot"
     md5_hashes="['a5e76221f6faf5c3e465b84b369685db', 'd7a55cc6c341b88d400cbe28121417fd', 'a1140f14987f9e9d0c2da5b78f9ffe3c']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(635904,1024) == "2d2d6b9da635f6b8d2e32b0dcf013556"
}

