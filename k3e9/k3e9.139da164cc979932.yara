import "hash"

rule k3e9_139da164cc979932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.139da164cc979932"
     cluster="k3e9.139da164cc979932"
     cluster_size="70 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['cedad97d4b8f6e1ad173ea2d9e98d3b9', 'ad628b34bb7af2e94efe83bf14cfcb2a', '5a83f3d6fefc04d557cfed8db0fcd9e4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(26624,1024) == "9d50f87de03c29a87bc27db9932cf548"
}

