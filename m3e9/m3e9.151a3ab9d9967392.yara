import "hash"

rule m3e9_151a3ab9d9967392
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.151a3ab9d9967392"
     cluster="m3e9.151a3ab9d9967392"
     cluster_size="24 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['be19f4f65750a1110fce390316914e22', 'bbbf159023d6a37b7eaaf32918a3d2a2', '2d0d6a2db4dc6e3318b3cc169e9d1f8b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(108544,1071) == "698123b4097303620115637265df5a66"
}

