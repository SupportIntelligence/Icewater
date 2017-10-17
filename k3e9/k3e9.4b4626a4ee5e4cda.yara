import "hash"

rule k3e9_4b4626a4ee5e4cda
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b4626a4ee5e4cda"
     cluster="k3e9.4b4626a4ee5e4cda"
     cluster_size="47 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['8ae88ccefa390d6e0fd79bb27fc37d1e', 'b6e4a07245bbddad0df7ac541082b179', 'd5da49afb299d5993899f3fa2ddccf73']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(38400,1280) == "8d605714fc674665af1478a4a862ce98"
}

