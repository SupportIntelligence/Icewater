import "hash"

rule m3e9_11b96924374d6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.11b96924374d6b16"
     cluster="m3e9.11b96924374d6b16"
     cluster_size="608 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="lethic kryptik zbot"
     md5_hashes="['bf750675648fa230e5eb73b903e5e360', 'adf0c29d915bc820a95ab5dfdbe80cde', 'a401877fb27703f12a6795176c30bd4c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62976,1024) == "8ae8aec016306e90a396cabc93d67bef"
}

