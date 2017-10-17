import "hash"

rule k3e9_52bd949396c31912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.52bd949396c31912"
     cluster="k3e9.52bd949396c31912"
     cluster_size="29 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['dcaaafd9806bb982e0b7b6e824643d08', 'af5a7bbed5bbb8e587ead511b06f23e8', '814f22fbb5bf0965da29994d53a45fd6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15360,1047) == "96961333556cba2129cd2d8aba66de1b"
}

