import "hash"

rule o3e7_61168408d992e112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.61168408d992e112"
     cluster="o3e7.61168408d992e112"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="generickd optimizerpro speedingupmypc"
     md5_hashes="['4862009de24b2fe206cfc891a719b23b', '2ddfca5989bf0a3982c585e0170c3cae', 'b7d14c9f8430820e9a1b5d654a5a4722']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(15458,1031) == "7588218093864576f4f128a2f6634cb6"
}

