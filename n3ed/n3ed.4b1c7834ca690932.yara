import "hash"

rule n3ed_4b1c7834ca690932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.4b1c7834ca690932"
     cluster="n3ed.4b1c7834ca690932"
     cluster_size="223 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="graftor malicious stantinko"
     md5_hashes="['5b3cf5355eee6e9a4612b324f16a2790', 'a28af16c7455b0e16394fdc19cb24073', '73d82fc205a72132acef3a934cebc15e']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(657920,1055) == "e7c95b4997f4027d537b12924a03e479"
}

