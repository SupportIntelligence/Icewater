import "hash"

rule o3e9_29b158728fa36d32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.29b158728fa36d32"
     cluster="o3e9.29b158728fa36d32"
     cluster_size="10 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['35ff18861b3d9ae4ed6808bf88db91d6', '9016c06148e14748e07f4db6e5e3ad15', 'a45f8e80f7b3788fd66a0e6c84073f7d']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(40999,1025) == "04259efeb8d17df605d1d07b9ff732f5"
}

