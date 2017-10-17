import "hash"

rule m3e9_721e28e8c99ce923
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.721e28e8c99ce923"
     cluster="m3e9.721e28e8c99ce923"
     cluster_size="230 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef vbkrypt"
     md5_hashes="['d02f2dc835e8a5b7bb5bd1c4fc1d7a3e', 'ab4746e84b297f6478e68b6dcbb07ca2', '0378a2787564a19b4a126bb858b981a3']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(153600,1024) == "0d9887826bce23c827fd93c62ace419b"
}

