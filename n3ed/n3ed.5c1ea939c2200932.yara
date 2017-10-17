import "hash"

rule n3ed_5c1ea939c2200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.5c1ea939c2200932"
     cluster="n3ed.5c1ea939c2200932"
     cluster_size="48 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bqjjnb"
     md5_hashes="['b9e42eefe72a8453dcf4ad638d2bd2fb', '73d056e5082c240f88940fe6c0f59792', '8cf994b2f3f06e6ec8fb040bfeb8a984']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(332800,1024) == "3eacbc4fc001d21d7f6b60c8cb4d7a59"
}

