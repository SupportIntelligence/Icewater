import "hash"

rule n3e9_610cee7ce22ed131
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.610cee7ce22ed131"
     cluster="n3e9.610cee7ce22ed131"
     cluster_size="132 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['b7efb4d5c2ba11efe9789f9a0de80460', 'f3bc55fb46378c892cf1219726b173c5', '0549815460f1f368d54ef756da4b99af']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(294912,1024) == "e9980409bd58ef812d6b8d5d6eaa1014"
}

