import "hash"

rule k3e9_1feb149bda2303b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1feb149bda2303b2"
     cluster="k3e9.1feb149bda2303b2"
     cluster_size="117 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre kryptik malicious"
     md5_hashes="['c8cec50b0494a4bd723b45050ef542ed', 'c500d6dd035c851bd167c4a9b726073d', '7f9288dedf025b833805eaa3a780919e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(14336,1024) == "b4cb0d3275824dae48a8c43d78b7c6bc"
}

