import "hash"

rule n3ed_0ca3390f1a12e132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a12e132"
     cluster="n3ed.0ca3390f1a12e132"
     cluster_size="329 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['38b59a72ffc348ddd8ab2a74c4acab91', '8defe5fd6da6a02e8cd09d0f9fd6454b', 'b0edd4a48b20c5ea57c484384137131e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(573952,1024) == "5ecc66daf37afcd45ee35aa85806cf8c"
}

