import "hash"

rule n3e9_39ca989982200932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.39ca989982200932"
     cluster="n3e9.39ca989982200932"
     cluster_size="13 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="zusy cuegoe malicious"
     md5_hashes="['da71160754b5ecf61983adddbe63bb51', 'a786c3dfa3315466c41831ff85eda6d0', '5542c222eda56e5f90c1ad59dc8e0a2d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(457216,1071) == "230f2ca45f5ff1772009485514dc5a76"
}

