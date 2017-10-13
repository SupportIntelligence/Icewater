import "hash"

rule n3e9_05b2594aeabb0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.05b2594aeabb0932"
     cluster="n3e9.05b2594aeabb0932"
     cluster_size="633 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy centrumloader unwanted"
     md5_hashes="['671f34a1daa673c9a38ac444af71d9a4', '6ecc4c679caba3e2a153f619c47d425f', '09439db47b339e9a2e22b928e92b6828']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(19474,1025) == "6cb794f2babb50c2a2135142afb9b98d"
}

