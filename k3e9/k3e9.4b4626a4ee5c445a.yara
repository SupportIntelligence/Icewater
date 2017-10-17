import "hash"

rule k3e9_4b4626a4ee5c445a
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee5c445a"
     cluster="k3e9.4b4626a4ee5c445a"
     cluster_size="18 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['4f8b91762c2955418bd68f3ad1876773', '4f8b91762c2955418bd68f3ad1876773', 'c86eff51f380689313e6a8e3b963310e']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(38400,1280) == "8d605714fc674665af1478a4a862ce98"
}

