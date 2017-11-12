import "hash"

rule m3ec_16931cc9cc00192a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.16931cc9cc00192a"
     cluster="m3ec.16931cc9cc00192a"
     cluster_size="6609 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="razy hupigon backdoor"
     md5_hashes="['11ce7ab3d0e90082b2d5c1d8eaaa88c9', '150a4808991a2ca8e9958893a8cdd9bf', '107e561079fb48fcba03ba2e8ffea492']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(67584,1024) == "021e4a586add72b7dd8002b5d4cf55c1"
}

