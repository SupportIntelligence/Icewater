import "hash"

rule m3e9_7a996b4bc54fcb12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.7a996b4bc54fcb12"
     cluster="m3e9.7a996b4bc54fcb12"
     cluster_size="583 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="chir cryptvittalia elex"
     md5_hashes="['b8259b86208f9ed149bba3c308386f61', 'bb70950a27059f5696e635138b6df7b4', 'ced3c40ce6b6a0ec5fbdae0a6a9f80e9']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(184832,1024) == "93613b1e670407aabe5ff4d0221f04d6"
}

