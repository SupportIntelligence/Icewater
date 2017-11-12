import "hash"

rule n3e9_2bb3549bc2201932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2bb3549bc2201932"
     cluster="n3e9.2bb3549bc2201932"
     cluster_size="62 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious kryptik attribute"
     md5_hashes="['051e7654b3352a4f7cc802d90389ffea', 'addc2938b173062949b33c168d98a1e3', '125e1b3ed9c795b1fba299c48a670121']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(198656,1024) == "159ccb2670c4f08d98c394bed9aa6159"
}

