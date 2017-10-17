import "hash"

rule n3e9_199a97c9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.199a97c9cc000b32"
     cluster="n3e9.199a97c9cc000b32"
     cluster_size="350 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="softonic bundler softonicdownloader"
     md5_hashes="['a47261672dd0bfd710ea7f4f938b1d0b', '261f45d02128ed9da2f81cca2377e18d', 'a1b119ebafd7c4b415d211866557f50e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(371098,1058) == "68a697bbf31e9cebab392314e3b7314a"
}

