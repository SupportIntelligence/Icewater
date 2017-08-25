import "hash"

rule n3e9_219b86b8d96b0b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.219b86b8d96b0b16"
     cluster="n3e9.219b86b8d96b0b16"
     cluster_size="109 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="malicious heuristic ardj"
     md5_hashes="['bb8176ceb75ba9a9c34509aae919dbd8', '62fbc03a93727192910ae7209e8c1875', '781bf1a23ec9238b4621575d68ed104a']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(634396,1038) == "e827fc2f771b5b6230e8d7644b923212"
}

