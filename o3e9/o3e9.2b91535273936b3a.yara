import "hash"

rule o3e9_2b91535273936b3a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2b91535273936b3a"
     cluster="o3e9.2b91535273936b3a"
     cluster_size="179 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster installmonstr malicious"
     md5_hashes="['cfafdc0808fc16c43d81b69087b39424', '4bade71a0cd1168e490cd6a026731a9c', 'eb9babdc80b7bc6a93ba00fb40fd5cd9']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2177536,1024) == "91c702cb3ec2428e045aabe4fc221a75"
}

