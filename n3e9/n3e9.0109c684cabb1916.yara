import "hash"

rule n3e9_0109c684cabb1916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0109c684cabb1916"
     cluster="n3e9.0109c684cabb1916"
     cluster_size="2176 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="syncopate unwanted malicious"
     md5_hashes="['0a23f29e941c391d3c047b373f188cc0', '01b7830fcc81d1527c516830be77389e', '114cf0d7383efe2119b6772f9ace6906']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(247808,1024) == "2306275f1f24b134aa32f904209844da"
}

