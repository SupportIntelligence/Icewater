import "hash"

rule n3e9_691a95b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.691a95b9c2200b12"
     cluster="n3e9.691a95b9c2200b12"
     cluster_size="127 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="erfmwp fixmypc malicious"
     md5_hashes="['9ed06b2634da2343f60d7ce6aa2981df', '43e8a37bbfa093be9c944df3dd5bf456', '5afb5b5efe3a056b2d0ad210e0ea2c34']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(97468,1026) == "511ffbfbc4e9fc04ce4101d3c66630d5"
}

