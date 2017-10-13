import "hash"

rule m3e9_012ccb12aa8d6b9e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.012ccb12aa8d6b9e"
     cluster="m3e9.012ccb12aa8d6b9e"
     cluster_size="461 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="shiz backdoor cridex"
     md5_hashes="['568886905e9b2a8eba9472f25ce61bb9', '8697dd4a1846348d8d546cf1848781f5', '0a3c8075112e7dd7dd618405dfc0c602']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(45056,1024) == "266f53029bd9b958c92d516755bed05b"
}

