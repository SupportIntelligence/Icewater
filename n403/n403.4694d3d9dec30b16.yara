import "hash"

rule n403_4694d3d9dec30b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n403.4694d3d9dec30b16"
     cluster="n403.4694d3d9dec30b16"
     cluster_size="398 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="crytex hublo geksone"
     md5_hashes="['26dec0c753d1030010043b9ff8abfdc5', '414722ee8d10c276d40bc7cd3bc3cec8', '42bd4b4b7b9253c8d483d1978feb3b72']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(371200,1050) == "40bbacf4c6d2344eb38a7aa2e42c6ec1"
}

