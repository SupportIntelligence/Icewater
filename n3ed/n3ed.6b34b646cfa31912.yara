import "hash"

rule n3ed_6b34b646cfa31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.6b34b646cfa31912"
     cluster="n3ed.6b34b646cfa31912"
     cluster_size="36 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="zusy malicious vundo"
     md5_hashes="['ad01df2adf6fdee05f0cabe0b95be0cf', '1e6f544aa9fcc8c4495f4320ee249bbe', '8fbc00bc37c0c2a180070adca1d84d48']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(201728,1024) == "308c5a39aef54df22728c431cba2f3c8"
}

