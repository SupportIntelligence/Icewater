import "hash"

rule n3e9_131c9cc9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.131c9cc9c4000b32"
     cluster="n3e9.131c9cc9c4000b32"
     cluster_size="220 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="viking jadtre nimnul"
     md5_hashes="['eba79f2ae0f458db62583b30d8727d79', 'c69bc7520c520b010f2713f0f929f883', 'ca5f09283c0bbbe6fb8e092bc424fbeb']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(71680,1024) == "df267315ded7f5392d705fd520e811af"
}

