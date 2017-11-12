import "hash"

rule n3e9_05b2594aeabb0932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.05b2594aeabb0932"
     cluster="n3e9.05b2594aeabb0932"
     cluster_size="1188 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy centrumloader unwanted"
     md5_hashes="['333c3fd80bcfd7df581fc0e5bc4b0741', '5907b627ddc9c720c8041096f331bc68', '044d78d7252e82afca088fae5fd46a14']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(19474,1025) == "6cb794f2babb50c2a2135142afb9b98d"
}

