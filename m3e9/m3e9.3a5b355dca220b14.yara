import "hash"

rule m3e9_3a5b355dca220b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5b355dca220b14"
     cluster="m3e9.3a5b355dca220b14"
     cluster_size="19 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qvod viking jadtre"
     md5_hashes="['b2a0c9799a13796a10b0ceb0384d6297', 'd83afe2e06ce24c578a4df11e03cf2df', 'cd166634a2dc2632fc54f660d564548b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

