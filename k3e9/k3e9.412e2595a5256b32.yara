import "hash"

rule k3e9_412e2595a5256b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.412e2595a5256b32"
     cluster="k3e9.412e2595a5256b32"
     cluster_size="49 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['d0073cc866f7b3c4f276c3ddb5e90a88', 'd63c950933cb010361fd9e2c73f25209', '8fb799c0f4749daa8b2b889a7d45c6b2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29526,1109) == "8a276caafdbf30bba5d7fac2a3e0c83d"
}

