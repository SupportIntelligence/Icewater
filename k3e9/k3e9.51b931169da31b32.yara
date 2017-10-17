import "hash"

rule k3e9_51b931169da31b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b931169da31b32"
     cluster="k3e9.51b931169da31b32"
     cluster_size="80 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['ce0b89e73e4e3da2e59cd33fde1792dd', 'd595898c132b7ec19e3588f43f88f2ff', 'cf68861f39fc4d4acaab658a714b289a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "a2c8c0039854981798c6825d650e8979"
}

