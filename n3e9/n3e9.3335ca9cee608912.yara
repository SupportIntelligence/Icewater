import "hash"

rule n3e9_3335ca9cee608912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3335ca9cee608912"
     cluster="n3e9.3335ca9cee608912"
     cluster_size="19387 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="downloadguide bundler downloaderguide"
     md5_hashes="['00ea7ca5ab9279964215a4319b2e6a2c', '026e12f4cdb5287c5f62f9086a71d3bd', '003ad5ef87b0a58bb5cfd9b0087c50f1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(535040,1024) == "54408539baf94b5661e46fba350c1782"
}

