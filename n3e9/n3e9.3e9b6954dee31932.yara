import "hash"

rule n3e9_3e9b6954dee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3e9b6954dee31932"
     cluster="n3e9.3e9b6954dee31932"
     cluster_size="39 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious startsurf afrm"
     md5_hashes="['0a57959bdd4fc22649333fd325d2ed83', '8586ce79ef37b6c8ea255f54ac07d6f5', 'a02cb550388082413363239d6ecf4721']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(355328,1127) == "edcf279e7f2f72f718be774faf39e6b1"
}

