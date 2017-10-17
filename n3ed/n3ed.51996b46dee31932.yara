import "hash"

rule n3ed_51996b46dee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b46dee31932"
     cluster="n3ed.51996b46dee31932"
     cluster_size="425 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a42dff1cd0e59f1316b2970491611929', '9436fd4a33f11344931093240d3082ec', 'b9a20f45c4e4a2cb58e0c4a154b4e1fe']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(340992,1024) == "dd91d06741e0bcecc34711b0e573b5c3"
}

