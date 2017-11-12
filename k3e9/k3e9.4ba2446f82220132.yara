import "hash"

rule k3e9_4ba2446f82220132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4ba2446f82220132"
     cluster="k3e9.4ba2446f82220132"
     cluster_size="12053 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="spyeyes upatre generickd"
     md5_hashes="['18b94806c436c9d1d114a0b00fc76044', '10e001f7533de69a603874e1ec3d9bc2', '161c0424de0a79a3a3b126ba71ac4f8b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(32745,1047) == "2f2e9c620045a129e014bb68d0c7f735"
}

