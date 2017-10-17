import "hash"

rule n3ed_531671a1c6000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.531671a1c6000b16"
     cluster="n3ed.531671a1c6000b16"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['bcf61e065770c32b20ee4e8422c25c9f', 'bcf61e065770c32b20ee4e8422c25c9f', 'aa771b7f731824c25cd16754865829f9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(135168,1024) == "52cb6988b2f04ce844376970cd99da9e"
}

