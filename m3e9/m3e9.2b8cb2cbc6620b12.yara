import "hash"

rule m3e9_2b8cb2cbc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2b8cb2cbc6620b12"
     cluster="m3e9.2b8cb2cbc6620b12"
     cluster_size="753 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="cripack tinba geri"
     md5_hashes="['1d536094a47dc3d2103439a9362c128f', 'af9690f2a45f85cea48b8e505bc2fcd7', '4996ae61be2b095ab410a517854543c6']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(110115,1059) == "0125969aaba32b9d7c36ccba8f294497"
}

