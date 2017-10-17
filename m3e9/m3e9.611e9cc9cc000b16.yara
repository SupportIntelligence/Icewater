import "hash"

rule m3e9_611e9cc9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e9cc9cc000b16"
     cluster="m3e9.611e9cc9cc000b16"
     cluster_size="202 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="allaple rahack backdoor"
     md5_hashes="['4dd7de3cddf7ed04e16a1227f4832bb5', 'a96d4ca3fdf93d1d7fb6e53c080ae61e', 'dbc39a11a1db4ecaa73ec66044458857']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(66200,1043) == "b5bc336a7b641cdd92b4153941c33c5a"
}

