import "hash"

rule k3e9_1b294366dd839112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b294366dd839112"
     cluster="k3e9.1b294366dd839112"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob malicious"
     md5_hashes="['7e0bdb3f67245024b57ab0a9aa1b471a', '7e0bdb3f67245024b57ab0a9aa1b471a', '7d77eb640bdbfea5899d70b770c34247']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(12288,1024) == "0449c30b832c1c60111f03ffa49ccd7d"
}

