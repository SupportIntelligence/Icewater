import "hash"

rule n3e7_06f611e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.06f611e9c8800b12"
     cluster="n3e7.06f611e9c8800b12"
     cluster_size="15 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="optimizerpro speedingupmypc riskware"
     md5_hashes="['55d45790830d9586f0dd0464e63a9a89', '9f5cb2cec30e280e4420e4e74f4987d9', '9f5cb2cec30e280e4420e4e74f4987d9']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(15458,1031) == "7588218093864576f4f128a2f6634cb6"
}

