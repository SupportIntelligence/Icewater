import "hash"

rule k3e9_412e1795a50d6b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.412e1795a50d6b32"
     cluster="k3e9.412e1795a50d6b32"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b27bf6223df386760f29f8bd5d92735a', '8480c5a1cde6f869364323448ad7724a', '32d7b6ba8769cf23af85a4a889cd6e47']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29526,1109) == "8a276caafdbf30bba5d7fac2a3e0c83d"
}

