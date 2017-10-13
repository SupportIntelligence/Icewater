import "hash"

rule n3e9_57eb203980800132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.57eb203980800132"
     cluster="n3e9.57eb203980800132"
     cluster_size="252 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['c883f5169f90dfd524f3edd36b0a914e', 'b9c559e38701f98f86d986a44068a21b', '216be426381b2742f601dc170d26b481']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(385853,1063) == "c1e6600333d0cb476facf5d80843907b"
}

