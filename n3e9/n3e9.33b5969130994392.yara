import "hash"

rule n3e9_33b5969130994392
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.33b5969130994392"
     cluster="n3e9.33b5969130994392"
     cluster_size="287 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="driverupdate fakedriverupdate heuristic"
     md5_hashes="['6c552ae89488ced0a346dbfb7427dc8a', '6565d881b7d58da203018e93185ad4f3', '0cd98be2f69965f1a1342caffa5701a4']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(450560,1024) == "aeb47d01f4d68794268a2f3ffcdda51c"
}

