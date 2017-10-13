import "hash"

rule m3e7_21146a48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e7.21146a48c0000b16"
     cluster="m3e7.21146a48c0000b16"
     cluster_size="34 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['b9b05dad6d9ed976c2d2938d3563ce19', 'd9ab5227d8b558a7ea190e1133553b66', 'bd07d0025e2f8979e4269fc08bc3254e']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62320,1115) == "6bdc6a4f47625879cbac9626b36ace17"
}

